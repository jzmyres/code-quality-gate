"""Result reuse by recorded reads.

The gate reads a store of records; a record is reused only when its program,
check, command and environment match and every recorded input still has the
same hash.  New records leave through a caller-owned descriptor, and the
trusted caller merges them with 'qg.py reuse merge'.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import ctypes
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import tracing
from .payload import PayloadError
from .policy import UsageError, _describe
from .tools import UnsupportedError, current_tools, tool_binary

SCHEMA = 1
LOCK_ENTRY = "strace"
_HEX = "0123456789abcdefABCDEF"
_RECORD_KEYS = {
    "schema",
    "program",
    "check",
    "command",
    "environment",
    "context",
    "inputs",
    "symlinks",
    "non_symlinks",
    "measurement",
    "tests_ran",
    "tests_skipped",
    "coverage_data",
    "coverage_config",
    "elisp_result",
    "emacs_version",
}


def _invalid_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _json_loads(text: str) -> Any:
    return json.loads(text, parse_constant=_invalid_constant)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def gate_program_hash() -> str:
    """The digest of qg.py and every module of the gate package."""
    from .trust import _gate_identity

    root = Path(__file__).resolve().parent.parent
    return str(_gate_identity(root)["digest"])


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_hash(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return _hash_file(path)
    except OSError:
        return "unreadable"


def _hash_directory(path: Path) -> str:
    digest = hashlib.sha256()
    for name in sorted(os.listdir(path)):
        digest.update(os.fsencode(name) + b"\0")
    return digest.hexdigest()


def current_input(path: str) -> tuple[bool, str | None]:
    """Return (found, digest) for PATH as a file or directory listing."""
    target = Path(path)
    try:
        if target.is_dir():
            return True, _hash_directory(target)
        if target.is_file():
            return True, _hash_file(target)
    except OSError:
        return False, None
    return False, None


def _input_matches(path: str, expected: str | None) -> bool:
    if expected == tracing.DIRECTORY_PRESENT:
        return os.path.isdir(path)
    found, actual = current_input(path)
    if expected is None:
        return not found and not os.path.lexists(path)
    return found and actual == expected


def _sha_digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in _HEX for character in value))


def _valid_digest(value: Any) -> bool:
    return value is None or value == tracing.DIRECTORY_PRESENT or _sha_digest(value)


def _inputs_match(inputs: Any) -> bool:
    if not isinstance(inputs, dict):
        return False
    for path, expected in inputs.items():
        if not isinstance(path, str) or not _valid_digest(expected):
            return False
        if not _input_matches(path, expected):
            return False
    return True


def _symlinks_match(symlinks: dict[str, str]) -> bool:
    try:
        return all(hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest() == digest
                   for path, digest in symlinks.items())
    except OSError:
        return False


def _non_symlinks_match(paths: list[str]) -> bool:
    return all(os.path.lexists(path) and not os.path.islink(path) for path in paths)


def _identity(record: dict[str, Any]) -> dict[str, Any] | None:
    keys = ("schema", "program", "check", "command", "environment", "context")
    if any(key not in record for key in keys):
        return None
    return {key: record[key] for key in keys}


def _spec_text(spec: Any) -> str:
    try:
        return json.dumps(asdict(spec), sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(spec)


def check_command(check: Any) -> list[str]:
    run = getattr(check.spec, "run", None)
    if run is not None:
        return [str(item) for item in run]
    return [str(check.adapter), _spec_text(check.spec)]


def _without_coverage(environment: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in environment.items()
        if not (name.startswith("COVERAGE_") and name != "COVERAGE_CORE")
    }


def check_environment(
    check: Any, root: Path | None = None, coverage_dir: Path | None = None
) -> dict[str, str]:
    environment = dict(os.environ)
    if check.adapter == "python_tests":
        from .python_tests import coverage_prefix_values

        assert root is not None and coverage_dir is not None
        environment = _without_coverage(environment)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["QG_PYTHON"] = json.dumps(
            coverage_prefix_values(root, coverage_dir / "data")
        )
    return dict(sorted(environment.items()))


def check_identity(
    check: Any, context: Any = None, root: Path | None = None,
    coverage_dir: Path | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "program": gate_program_hash(),
        "check": str(check.id),
        "command": check_command(check),
        "environment": check_environment(check, root, coverage_dir),
        "context": hashlib.sha256(_canonical(context)).hexdigest(),
    }


def _non_dumpable() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise UsageError(f"reuse: cannot make gate non-dumpable: {os.strerror(error)}")


def _record_fd(fd: int) -> None:
    if fd < 3:
        raise UsageError(
            f"qg.py: --record-fd {fd}: expected a descriptor at least 3"
        )
    try:
        os.fstat(fd)
    except OSError as error:
        raise UsageError(
            f"qg.py: --record-fd {fd}: expected an open descriptor, got "
            f"{error}"
        ) from error
    try:
        os.set_inheritable(fd, False)
    except OSError as error:
        raise UsageError(
            f"qg.py: --record-fd {fd}: expected a usable descriptor, got "
            f"{error}"
        ) from error
    tracing.register_child_fd(fd)


@dataclass
class Reused:
    tree: Path
    record: dict[str, Any]


class _CoverageDirectory:
    def __init__(self, path: Path) -> None:
        self.name: str | None = None
        path.mkdir(mode=0o700)
        self.name = str(path)

    def cleanup(self) -> None:
        if self.name is not None:
            shutil.rmtree(self.name, ignore_errors=True)

    def __del__(self) -> None:
        self.cleanup()


@dataclass
class ReuseSession:
    store: Path
    root: Path
    record_fd: int | None = None
    prune_id: str | None = None
    program: str = field(default="")
    temporary: tempfile.TemporaryDirectory[str] = field(
        default_factory=lambda: tempfile.TemporaryDirectory(prefix="qg-reuse-")
    )
    tracer: tuple[str, ...] = ()
    temporary_paths: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.store = self.store.expanduser().absolute()
        self.program = gate_program_hash()
        if self.record_fd is not None:
            _record_fd(self.record_fd)
        _non_dumpable()

    def close(self) -> None:
        if self.record_fd is not None:
            tracing.unregister_child_fd(self.record_fd)
            with contextlib.suppress(OSError):
                os.close(self.record_fd)
            self.record_fd = None
        self.temporary.cleanup()

    def coverage_path(self, check: Any) -> Path:
        identity = [self.program, str(self.root), str(check.id), dict(sorted(os.environ.items()))]
        key = hashlib.sha256(_canonical(identity)).hexdigest()
        return Path(tempfile.gettempdir()) / f"qg-coverage-{key}"

    def coverage_directory(self, check: Any) -> Any:
        path = self.coverage_path(check)
        try:
            temporary = _CoverageDirectory(path)
        except FileExistsError:
            temporary = tempfile.TemporaryDirectory(prefix="qg-coverage-")
        assert temporary.name is not None
        self.temporary_paths.add(temporary.name)
        recorder = tracing.current()
        if recorder is not None:
            recorder.temporary_paths.add(temporary.name)
        return temporary

    def _require_tracer(self) -> tuple[str, ...]:
        lock, _tools = current_tools()
        try:
            binary = tool_binary(LOCK_ENTRY)
        except (UnsupportedError, PayloadError) as error:
            raise tracing.TraceUnavailable(
                f"reuse: {lock} [{LOCK_ENTRY}]: expected the pinned tracer, "
                f"got {error}"
            ) from error
        self.tracer = (str(binary),)
        return self.tracer

    @contextlib.contextmanager
    def collect(self, check: Any, tracer: tuple[str, ...]) -> Iterator[tracing.Recorder]:
        with tracing.collecting(
            self.root, Path(self.temporary.name), tracer,
            tuple(sorted(self.temporary_paths)),
        ) as recorder:
            try:
                yield recorder
            finally:
                self.temporary_paths.update(recorder.temporary_paths)

    def _records(self) -> list[Path]:
        try:
            entries = list(os.scandir(self.store))
        except OSError:
            return []
        return sorted(
            Path(entry.path) / "record.json"
            for entry in entries
            if entry.is_dir(follow_symlinks=False)
        )

    def lookup(self, identity: dict[str, Any]) -> Reused | None:
        for path in self._records():
            record = _load_record(path)
            if _record_matches(record, identity):
                return Reused(path.parent, record)
        return None

    def record(
        self, identity: dict[str, Any], recorder: tracing.Recorder, result: Any
    ) -> None:
        if self.record_fd is None:
            return
        if recorder.environment is not None:
            identity = dict(identity, environment=recorder.environment)
        try:
            document = _record_document(identity, recorder, result)
        except OSError:
            return
        line = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            + b"\n"
        )
        _write_line(self.record_fd, line)


def _record_matches(record: dict[str, Any] | None, identity: dict[str, Any]) -> bool:
    if record is None or _identity(record) != identity:
        return False
    return (_inputs_match(record["inputs"]) and _symlinks_match(record["symlinks"])
            and _non_symlinks_match(record["non_symlinks"]))


def _load_record(path: Path) -> dict[str, Any] | None:
    try:
        record = _json_loads(path.read_text(encoding="utf-8"))
        return _validate_record(record, path, 1)
    except (OSError, ValueError, UsageError):
        return None


def _record_evidence(document: dict[str, Any], result: Any) -> None:
    evidence = getattr(result, "evidence_path", None)
    if evidence is None:
        return
    configuration = getattr(result, "coverage_config", None)
    if configuration is not None:
        document["coverage_data"] = base64.b64encode(evidence.read_bytes()).decode("ascii")
        document["coverage_config"] = base64.b64encode(configuration.read_bytes()).decode("ascii")
    elif getattr(result, "adapter", None) == "elisp_tests":
        document["elisp_result"] = _json_loads(evidence.read_text(encoding="utf-8"))


def _record_document(
    identity: dict[str, Any], recorder: tracing.Recorder, result: Any
) -> dict[str, Any]:
    document = dict(identity)
    document["inputs"] = recorder.snapshot()
    document["symlinks"] = dict(sorted(recorder.symlinks.items()))
    document["non_symlinks"] = sorted(recorder.non_symlinks)
    _record_evidence(document, result)
    if getattr(result, "measurement", None) is not None:
        document["measurement"] = result.measurement
    if getattr(result, "emacs_version", None) is not None:
        document["emacs_version"] = result.emacs_version
    for name in ("tests_ran", "tests_skipped"):
        value = getattr(result, name, None)
        if value is not None:
            document[name] = value
    return document


def _write_line(fd: int, line: bytes) -> None:
    try:
        while line:
            line = line[os.write(fd, line) :]
    except OSError as error:
        raise UsageError(
            f"qg.py: --record-fd {fd}: cannot write a record: {error}"
        ) from error


_session: ReuseSession | None = None


def current() -> ReuseSession | None:
    return _session


@contextlib.contextmanager
def active(
    store: Path | None, root: Path, record_fd: int | None,
    prune_id: str | None = None,
) -> Iterator[ReuseSession | None]:
    global _session
    if store is None:
        yield None
        return
    session = ReuseSession(store, root, record_fd, prune_id)
    previous = _session
    _session = session
    try:
        yield session
    finally:
        _session = previous
        session.close()


def _values_from_document(document: Any) -> list[Any]:
    if isinstance(document, dict) and isinstance(document.get("records"), list):
        return document["records"]
    if isinstance(document, list):
        return document
    return [document]


def _parse_line(line: str, source: Path, number: int) -> Any:
    try:
        return _json_loads(line)
    except ValueError as error:
        raise UsageError(
            f"{source}:{number}: expected a JSON record, got {error}"
        ) from error


def _line_records(
    text: str, source: Path
) -> list[tuple[int, Any]]:
    records: list[tuple[int, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            records.append((number, _parse_line(line, source, number)))
    return records


def _record_lines(text: str, source: Path) -> list[tuple[int, Any]]:
    try:
        document = _json_loads(text)
    except ValueError:
        return _line_records(text, source)
    return list(enumerate(_values_from_document(document), 1))


def _validate_hex(value: Any, key: str, source: str, number: int) -> str:
    if not (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    ):
        raise UsageError(
            f"{source}:{number}: {key}: expected a 64-character hexadecimal "
            f"SHA-256, got {_describe(value)}"
        )
    return value.lower()


def _validate_command(value: Any, source: str, number: int) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise UsageError(
            f"{source}:{number}: command: expected a list of strings, got "
            f"{_describe(value)}"
        )
    return value


def _validate_environment(value: Any, source: str, number: int) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    ):
        raise UsageError(
            f"{source}:{number}: environment: expected a table of strings, "
            f"got {_describe(value)}"
        )
    return value


def _input_digest(
    digest: Any, path: str, source: str, number: int
) -> str | None:
    if digest is None or digest == tracing.DIRECTORY_PRESENT:
        return digest
    return _validate_hex(digest, f"inputs[{path!r}]", source, number)


def _input_path(path: Any, source: str, number: int) -> str:
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise UsageError(
            f"{source}:{number}: inputs: expected absolute normalized paths, got {_describe(path)}"
        )
    return path


def _validate_inputs(value: Any, source: str, number: int) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise UsageError(f"{source}:{number}: inputs: expected a table, got {_describe(value)}")
    return {_input_path(path, source, number): _input_digest(digest, path, source, number)
            for path, digest in value.items()}


def _validate_non_symlinks(value: Any, source: str, number: int) -> list[str]:
    if not isinstance(value, list):
        raise UsageError(f"{source}:{number}: non_symlinks: expected an array of paths")
    paths = [_input_path(path, source, number) for path in value]
    if len(paths) != len(set(paths)):
        raise UsageError(f"{source}:{number}: non_symlinks: duplicate paths")
    return paths


def _record_keys(value: dict[str, Any], source: Path, number: int) -> None:
    unknown = sorted(set(value) - _RECORD_KEYS)
    if unknown:
        raise UsageError(
            f"{source}:{number}: unknown record keys: {', '.join(unknown)}"
        )


def _required_keys(value: dict[str, Any], source: Path, number: int) -> None:
    keys = ("schema", "program", "check", "command", "environment", "context",
            "inputs", "symlinks", "non_symlinks")
    for key in keys:
        if key not in value:
            raise UsageError(f"{source}:{number}: {key}: missing")


def _validate_schema(value: Any, source: Path, number: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != SCHEMA:
        raise UsageError(
            f"{source}:{number}: schema: expected {SCHEMA}, got "
            f"{_describe(value)}"
        )


def _validate_check(value: Any, source: Path, number: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UsageError(
            f"{source}:{number}: check: expected a non-empty string, got "
            f"{_describe(value)}"
        )
    return value


def _validate_measurement(value: Any, source: Path, number: int) -> Any:
    if value is not None and not isinstance(value, dict):
        raise UsageError(
            f"{source}:{number}: measurement: expected a table, got "
            f"{_describe(value)}"
        )
    return value


def _validate_count(name: str, value: Any, source: Path, number: int) -> Any:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value < 0
    ):
        raise UsageError(
            f"{source}:{number}: {name}: expected a non-negative integer, got "
            f"{_describe(value)}"
        )
    return value


def _validate_base64(value: Any, name: str, source: Path, number: int) -> str:
    try:
        if not isinstance(value, str) or not base64.b64decode(value, validate=True):
            raise ValueError("empty or invalid data")
    except (ValueError, binascii.Error) as error:
        raise UsageError(f"{source}:{number}: {name}: invalid base64 evidence") from error
    return value


def _coverage_pair(fields: Any, present: Any, source: Path, number: int) -> None:
    if len(present) != len(fields):
        raise UsageError(f"{source}:{number}: coverage evidence requires both fields")


def _validate_coverage(value: dict[str, Any], record: dict[str, Any], source: Path, number: int) -> None:
    fields = ("coverage_data", "coverage_config")
    present = [name for name in fields if name in value]
    if present:
        _coverage_pair(fields, present, source, number)
    for name in present:
        record[name] = _validate_base64(value[name], name, source, number)


def restore_coverage(record: dict[str, Any], result: Any) -> None:
    if "coverage_data" not in record:
        return
    temporary = tempfile.TemporaryDirectory(prefix="qg-coverage-")
    root = Path(temporary.name)
    result.evidence_path = root / ".coverage"
    result.coverage_config = root / "coverage.ini"
    result.evidence_path.write_bytes(base64.b64decode(record["coverage_data"]))
    result.coverage_config.write_bytes(base64.b64decode(record["coverage_config"]))
    result.temporary = temporary
    session = current()
    if session is not None:
        session.temporary_paths.add(str(root))


def restore_elisp(record: dict[str, Any], result: Any) -> None:
    temporary = tempfile.TemporaryDirectory(prefix="qg-elisp-")
    root = Path(temporary.name)
    result.evidence_path = root / "result.json"
    result.evidence_path.write_bytes(_canonical(record["elisp_result"]))
    result.temporary = temporary
    session = current()
    if session is not None:
        session.temporary_paths.add(str(root))


def _elisp_record_fields(value: dict[str, Any], record: dict[str, Any], source: Path, number: int) -> None:
    if "elisp_result" not in value:
        return
    from .elisp_tests import validate_reused_document

    try:
        record["elisp_result"] = validate_reused_document(value["elisp_result"])
    except ValueError as error:
        raise UsageError(
            f"{source}:{number}: elisp_result: expected valid evidence, got {error}"
        ) from error


def _optional_fields(
    value: dict[str, Any], record: dict[str, Any], source: Path, number: int
) -> None:
    _elisp_record_fields(value, record, source, number)
    if "emacs_version" in value:
        record["emacs_version"] = _validate_emacs_version(value["emacs_version"], source, number)
    if "measurement" in value:
        record["measurement"] = _validate_measurement(
            value["measurement"], source, number
        )
    for name in ("tests_ran", "tests_skipped"):
        if name in value:
            record[name] = _validate_count(name, value[name], source, number)


def _validate_emacs_version(value: Any, source: Path, number: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UsageError(
            f"{source}:{number}: emacs_version: expected a non-empty string, got {_describe(value)}"
        )
    return value


def _invalid_symlink_digest(digest: Any) -> bool:
    return digest is None or digest == tracing.DIRECTORY_PRESENT


def _validate_link_types(record: dict[str, Any], source: Path, number: int) -> None:
    if any(_invalid_symlink_digest(digest) for digest in record["symlinks"].values()):
        raise UsageError(f"{source}:{number}: symlinks: expected SHA-256 digests")
    if set(record["symlinks"]).intersection(record["non_symlinks"]):
        raise UsageError(f"{source}:{number}: conflicting symlink types")


def _validate_record(value: Any, source: Path, number: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UsageError(
            f"{source}:{number}: expected a record table, got "
            f"{_describe(value)}"
        )
    _record_keys(value, source, number)
    _required_keys(value, source, number)
    _validate_schema(value["schema"], source, number)
    check = _validate_check(value["check"], source, number)
    record = {
        "schema": SCHEMA,
        "program": _validate_hex(value["program"], "program", str(source), number),
        "check": check,
        "command": _validate_command(value["command"], str(source), number),
        "environment": _validate_environment(
            value["environment"], str(source), number
        ),
        "context": _validate_hex(value["context"], "context", str(source), number),
        "inputs": _validate_inputs(value["inputs"], str(source), number),
        "symlinks": _validate_inputs(value["symlinks"], str(source), number),
        "non_symlinks": _validate_non_symlinks(value["non_symlinks"], str(source), number),
    }
    _validate_link_types(record, source, number)
    _optional_fields(value, record, source, number)
    _validate_coverage(value, record, source, number)
    return record


def _validate_entries(
    entries: list[tuple[int, Any]], source: Path
) -> list[dict[str, Any]]:
    expected = gate_program_hash()
    records: list[dict[str, Any]] = []
    for number, value in entries:
        record = _validate_record(value, source, number)
        if record["program"] != expected:
            raise UsageError(
                f"{source}:{number}: program: expected this gate program "
                f"{expected}, got {record['program']}"
            )
        records.append(record)
    return records


def _record_tree(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _write_record(store: Path, record: dict[str, Any]) -> bool:
    tree = _record_tree(record)
    directory = store / tree
    destination = directory / "record.json"
    payload = _canonical(record) + b"\n"
    if destination.is_file() and destination.read_bytes() == payload:
        return False
    directory.mkdir(mode=0o755, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(directory, stat.S_IRWXU)
    temporary = directory / ".record.tmp"
    temporary.write_bytes(payload)
    os.chmod(temporary, 0o444)
    os.replace(temporary, destination)
    os.chmod(directory, 0o555)
    return True


def _read_record_file(source: Path) -> str:
    try:
        return source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise UsageError(
            f"{source}: expected a readable record file, got {error}"
        ) from error


def _prepare_store(store: Path) -> Path:
    store = store.expanduser().absolute()
    if store.exists() and not store.is_dir():
        raise UsageError(f"{store}: expected a directory, got a file")
    store.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(store, stat.S_IRWXU)
    except OSError:
        pass
    return store


def _write_records(
    store: Path, records: list[dict[str, Any]]
) -> int:
    return sum(1 for record in records if _write_record(store, record))


def merge_records(store: Path, source: Path) -> int:
    text = _read_record_file(source)
    records = _validate_entries(_record_lines(text, source), source)
    store = _prepare_store(store)
    written = _write_records(store, records)
    with contextlib.suppress(OSError):
        os.chmod(store, 0o555)
    print(f"reuse: merged {written} records into {store}")
    return 0
