"""The trust root: protected inputs, effective inputs and run identity.

With --policy-from DIR the gate evaluates the candidate working tree against
the policy, baselines and tool lock in a trusted directory, refusing to trust
a candidate's copy of an input another program reads or executes.
"""
from __future__ import annotations

import errno
import fnmatch
import hashlib
import json
import os
import posixpath
import stat
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from . import tools as tools_module
from .files import _type_name, git_argv
from .payload import PayloadError
from .policy import Config, ConfigError, GateError, UsageError, load_config
from .ratchet import BaselineEntry, load_baseline, tighter_bound
from .runner import RunResult, run
from .tools import Tool, _default_lock_path, _tool_payload_digest, _tools_dir, load_tools

POLICY_NAME = "quality-gate.toml"
LOCK_NAME = "tools.lock.toml"
RESULT_SCHEMA = 3


@dataclass(frozen=True)
class ProtectedInput:
    path: str
    kind: str
    rev_sha256: str | None
    candidate_sha256: str | None
    status: str
    ignored_entries: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "path": self.path,
            "rev_sha256": self.rev_sha256,
            "candidate_sha256": self.candidate_sha256,
            "status": self.status,
        }
        if self.kind == "baseline":
            document["ignored_entries"] = list(self.ignored_entries)
        return document


def _blocked_paths(protected: list[ProtectedInput]) -> list[str]:
    return [item.path for item in protected if item.status == "blocked"]


def _file_description(sha256: str | None) -> str:
    return f"file {sha256}" if sha256 is not None else "missing -"


def _not_applied(item: ProtectedInput) -> str:
    if not item.ignored_entries:
        return ""
    return "; not applied: " + ", ".join(item.ignored_entries)


def _report_blocked_detail(item: ProtectedInput) -> None:
    print(
        f"check: protected input {item.path}: REV "
        f"{_file_description(item.rev_sha256)}; candidate "
        f"{_file_description(item.candidate_sha256)}"
        f"{_not_applied(item)}; {item.status}",
        file=sys.stderr,
    )


@dataclass
class Trust:
    root: Path
    revision: str
    config: Config
    rev_config: Config
    protected: list[ProtectedInput]
    lock_path: Path
    lock_tools: dict[str, Tool]
    reader: _TrustedTree
    trusted: Path
    temporary: list[tempfile.TemporaryDirectory[str]] = field(
        default_factory=list
    )
    identity_before: dict[str, Any] | None = None
    identity_after: dict[str, Any] | None = None

    def activate(self):
        return tools_module.lock_override(self.lock_path, self.lock_tools)

    @property
    def policy_sha256(self) -> str | None:
        assert self.identity_before is not None
        return self.identity_before["effective_inputs"][f"policy {POLICY_NAME}"]

    def close(self) -> None:
        for directory in reversed(self.temporary):
            directory.cleanup()

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.trusted),
            "digest": self.reader.digest(),
            "protected": [item.to_json() for item in self.protected],
            "identity_before": self.identity_before,
            "identity_after": self.identity_after,
        }

    def report_blocked(self) -> bool:
        blocked = _blocked_paths(self.protected)
        if not blocked:
            return False
        for item in self.protected:
            if item.status == "blocked":
                _report_blocked_detail(item)
        print(
            f"check: blocked: protected input changed without "
            f"--allow-protected: {', '.join(blocked)}",
            file=sys.stderr,
        )
        return True

    def finish(
        self, code: int, document: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        after = _capture_identity(self)
        problems = _identity_problems(self.identity_before or {}, after)
        self.identity_after = after
        document["schema"] = RESULT_SCHEMA
        document["trust"] = self.to_json()
        if problems:
            message = "; ".join(problems)
            print(f"check: error: {message}", file=sys.stderr)
            document["decision"] = "error"
            document["error"] = message
            return 2, document
        if self.report_blocked():
            document["decision"] = "blocked"
            return 1, document
        return code, document


@dataclass(frozen=True)
class _Input:
    path: str
    kind: str
    rev_sha256: str | None
    candidate_sha256: str | None


def _git(root: Path, args: list[str]) -> RunResult:
    return run(
        git_argv(root, *args),
        budget_seconds=600,
        capture_limit=None,
    )


def _git_detail(result: RunResult) -> str:
    return result.stderr_text.strip() or f"git exited {result.returncode}"


class _TrustedTree:
    """Plain reads of a caller-supplied extracted tree; symlinks are not followed."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.location = str(root)
        self._reads: dict[str, bytes] = {}

    def _regular(self, path: Path) -> bool:
        try:
            return stat.S_ISREG(path.lstat().st_mode)
        except OSError:
            return False

    def files(self) -> list[str]:
        names: list[str] = []
        for directory, _directories, files in os.walk(self.root):
            for name in files:
                path = Path(directory) / name
                if self._regular(path):
                    names.append(path.relative_to(self.root).as_posix())
        return names

    def _read_file(self, path: Path) -> bytes | None:
        try:
            handle = os.open(
                path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
        except OSError:
            return None
        try:
            with os.fdopen(handle, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return None
                return stream.read()
        except OSError as error:
            raise UsageError(
                f"{path}: --policy-from: expected a readable trusted "
                f"file, got {error}"
            ) from error

    def read(self, relative: str) -> bytes | None:
        if relative in self._reads:
            return self._reads[relative]
        path = _safe_join(self.root, relative)
        if path is None or not self._regular(path):
            return None
        data = self._read_file(path)
        if data is not None:
            self._reads[relative] = data
        return data

    def digest(self) -> str:
        encoded = "".join(
            f"{relative}\0{_sha256(data)}\n"
            for relative, data in sorted(self._reads.items())
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _candidate_files(root: Path) -> list[str]:
    # The protected scope includes ignored untracked files, so no
    # --exclude-standard here.
    result = _git(root, ["ls-files", "-z", "-c", "-o"])
    if result.execution != "completed" or result.returncode != 0:
        raise UsageError(
            f"{root}: cannot list the candidate: {_git_detail(result)}"
        )
    return [
        item for item in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if item
    ]


def _candidate_error(path: Path, detail: str) -> UsageError:
    return UsageError(
        f"{path}: protected input: expected a regular file inside the "
        f"candidate, got {detail}"
    )


def _kind_name(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "a directory"
    name = _type_name(mode)
    return f"a {name}" if name else "a non-regular file"


def _parent_mode(path: Path) -> int | None:
    try:
        return path.lstat().st_mode
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _candidate_error(path, str(error)) from error


def _candidate_parent(root: Path, relative: str) -> Path | None:
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        mode = _parent_mode(current)
        if mode is None:
            return None
        if stat.S_ISLNK(mode):
            raise _candidate_error(
                root / relative, f"a symlinked parent {current}"
            )
        if not stat.S_ISDIR(mode):
            return None
    return current


def _open_candidate(path: Path) -> int | None:
    try:
        return os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise _candidate_error(path, "a symlink") from error
        raise _candidate_error(path, str(error)) from error


def _read_regular(path: Path) -> bytes | None:
    handle = _open_candidate(path)
    if handle is None:
        return None
    try:
        mode = os.fstat(handle).st_mode
        if not stat.S_ISREG(mode):
            raise _candidate_error(path, _kind_name(mode))
        with os.fdopen(handle, "rb") as stream:
            handle = -1
            return stream.read()
    finally:
        if handle >= 0:
            os.close(handle)


def _candidate_path(root: Path, relative: str) -> Path | None:
    path = _safe_join(root, relative)
    if path is None:
        raise _candidate_error(
            root / relative, "a path outside the candidate"
        )
    if _candidate_parent(root, relative) is None:
        return None
    return path


def _candidate_bytes(root: Path, relative: str) -> bytes | None:
    path = _candidate_path(root, relative)
    if path is None:
        return None
    return _read_regular(path)


def _sha256(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _normalise(path: str) -> str:
    return posixpath.normpath(path)


def _has_magic(pattern: str) -> bool:
    return any(character in pattern for character in "*?[")


def _expand_protect(
    patterns: tuple[str, ...], root: Path, source: _TrustedTree
) -> set[str]:
    protected: set[str] = set()
    globs: list[str] = []
    for pattern in patterns:
        if _has_magic(pattern):
            globs.append(pattern)
        else:
            protected.add(_normalise(pattern))
    if not globs:
        return protected
    names = set(source.files()) | set(_candidate_files(root))
    for pattern in globs:
        protected.update(fnmatch.filter(names, pattern))
    return protected


def _baseline_names(config: Config) -> set[str]:
    names: set[str] = set()
    for check in config.checks.values():
        if check.baseline is None:
            continue
        try:
            relative = check.baseline.relative_to(config.root)
        except ValueError:
            raise UsageError(
                f"{config.path}: checks.{check.id}.baseline: expected a path "
                f"inside the repository root, got {check.baseline}"
            ) from None
        names.add(relative.as_posix())
    return names


def _protected_scope(
    root: Path, source: _TrustedTree, config: Config
) -> set[str]:
    paths = {POLICY_NAME, LOCK_NAME} | _baseline_names(config)
    return paths | _expand_protect(config.protect_paths, root, source)


def _input_kind(path: str, baselines: set[str]) -> str:
    if path == POLICY_NAME:
        return "policy"
    if path == LOCK_NAME:
        return "lock"
    return "baseline" if path in baselines else "other"


def _protected_input(
    root: Path, source: _TrustedTree, path: str, kind: str
) -> _Input:
    return _Input(
        path, kind, _sha256(source.read(path)),
        _sha256(_candidate_bytes(root, path)),
    )


def _protected_inputs(
    root: Path, source: _TrustedTree, config: Config
) -> dict[str, _Input]:
    baselines = _baseline_names(config)
    return {
        path: _protected_input(root, source, path, _input_kind(path, baselines))
        for path in sorted(_protected_scope(root, source, config))
    }


def _input_changed(item: _Input) -> bool:
    return item.rev_sha256 != item.candidate_sha256


def _declared_status(item: _Input, allowed: set[str]) -> str:
    if not _input_changed(item):
        return "unchanged"
    if item.path in allowed:
        return "authorized"
    return "blocked"


def _policy_baseline_names(data: dict[str, Any]) -> tuple[str, ...]:
    checks = data.get("checks")
    if not isinstance(checks, dict):
        return ()
    names: list[str] = []
    for raw in checks.values():
        if isinstance(raw, dict) and isinstance(raw.get("baseline"), str):
            names.append(raw["baseline"])
    return tuple(names)


def _safe_join(root: Path, relative: str) -> Path | None:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return root.joinpath(*path.parts)


def _materialize(
    policy_root: Path,
    root: Path,
    source: _TrustedTree,
    policy: bytes,
) -> None:
    (policy_root / POLICY_NAME).write_bytes(policy)
    try:
        data = tomllib.loads(policy.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ConfigError(
            f"{root / POLICY_NAME} at {source.location}: expected valid TOML, got "
            f"{error}"
        ) from error
    for name in _policy_baseline_names(data):
        raw = source.read(name)
        target = _safe_join(policy_root, name)
        if raw is None or target is None:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def _policy_config(
    root: Path,
    rev_config: Config,
    inputs: dict[str, _Input],
    allowed: set[str],
) -> tuple[Config, str]:
    item = inputs[POLICY_NAME]
    if not _input_changed(item):
        return rev_config, "unchanged"
    if POLICY_NAME in allowed:
        return load_config(root, validate_headers=False), "authorized"
    return rev_config, "blocked"


def _entries_from_bytes(
    temporary: Path,
    tag: str,
    raw: bytes,
    check: Any,
) -> list[BaselineEntry]:
    name = hashlib.sha256(f"{tag}\0{check.id}".encode()).hexdigest()[:16]
    path = temporary / f"{name}.toml"
    path.write_bytes(raw)
    from .adapters import adapter_for

    descriptor = adapter_for(check.adapter)
    extras = descriptor.extras if descriptor is not None else ()
    return load_baseline(
        path,
        check_id=check.id,
        metric_version=check.metric_version,
        allowed_extras=extras,
        adapter=check.adapter,
        direction=check.direction,
    )


def _rev_entries(
    temporary: Path,
    source: _TrustedTree,
    relative: str,
    check: Any,
) -> list[BaselineEntry]:
    raw = source.read(relative)
    if raw is None:
        return []
    try:
        return _entries_from_bytes(temporary, "rev", raw, check)
    except GateError as error:
        raise UsageError(
            f"{relative} at {source.location}: expected a valid baseline, "
            f"got {error}"
        ) from error


def _candidate_entries(
    temporary: Path, root: Path, relative: str, check: Any
) -> tuple[list[BaselineEntry], bool]:
    raw = _candidate_bytes(root, relative)
    if raw is None:
        return [], False
    try:
        return _entries_from_bytes(temporary, "candidate", raw, check), False
    except GateError as error:
        print(
            f"check: {relative}: candidate baseline not applied: {error}",
            file=sys.stderr,
        )
        return [], True


def _tighter_expiry(
    revision: Any, candidate: Any
) -> Any:
    if candidate is None or (revision is not None and revision <= candidate):
        return revision
    return candidate


def _merge_entry(
    entry: BaselineEntry,
    chosen: BaselineEntry,
    direction: str = "max",
) -> tuple[BaselineEntry, bool, bool]:
    merged = replace(
        entry,
        bound=tighter_bound(entry.bound, chosen.bound, direction),
        expires=_tighter_expiry(entry.expires, chosen.expires),
    )
    return merged, merged != entry, merged != chosen


def _merge_revision_entry(
    entry: BaselineEntry,
    remaining: dict[str, BaselineEntry],
    check: Any,
) -> tuple[list[BaselineEntry], list[str], bool]:
    chosen = remaining.pop(entry.subject, None)
    direction = entry.direction
    if chosen is None:
        if direction == "min":
            return [entry], [entry.subject], False
        return [], [], True
    merged_entry, tightened, ignored = _merge_entry(
        entry, chosen, direction
    )
    return [merged_entry], [entry.subject] if ignored else [], tightened


def _merge_entries(
    revision: list[BaselineEntry],
    candidate: list[BaselineEntry],
    check: Any = None,
) -> tuple[list[BaselineEntry], tuple[str, ...], bool]:
    remaining = {entry.subject: entry for entry in candidate}
    merged: list[BaselineEntry] = []
    ignored: list[str] = []
    tightened = False
    for entry in revision:
        entries, subjects, entry_tightened = _merge_revision_entry(
            entry, remaining, check
        )
        merged.extend(entries)
        ignored.extend(subjects)
        tightened = tightened or entry_tightened
    ignored.extend(sorted(remaining))
    return merged, tuple(ignored), tightened


def _check_baseline_name(check: Any, config_root: Path) -> str | None:
    if check.baseline is None:
        return None
    try:
        return check.baseline.relative_to(config_root).as_posix()
    except ValueError:
        return None


def _baseline_status(
    item: _Input, tightened: bool, ignored: tuple[str, ...], invalid: bool
) -> str:
    if not _input_changed(item):
        return "unchanged"
    if tightened and not ignored and not invalid:
        return "tightened"
    return "blocked"


def _merged_baseline(
    temporary: Path,
    root: Path,
    source: _TrustedTree,
    relative: str,
    check: Any,
    item: _Input,
) -> tuple[list[BaselineEntry], str, tuple[str, ...]]:
    revision_entries = _rev_entries(temporary, source, relative, check)
    candidate_entries, invalid = _candidate_entries(
        temporary, root, relative, check
    )
    if invalid:
        merged, ignored, tightened = revision_entries, (), False
    else:
        merged, ignored, tightened = _merge_entries(
            revision_entries, candidate_entries, check
        )
    return (
        merged,
        _baseline_status(item, tightened, ignored, invalid),
        ignored,
    )


def _required_candidate_entries(
    temporary: Path, root: Path, relative: str, check: Any
) -> list[BaselineEntry]:
    raw = _candidate_bytes(root, relative)
    if raw is None:
        return []
    try:
        return _entries_from_bytes(temporary, "authorized", raw, check)
    except GateError as error:
        raise UsageError(
            f"{relative}: expected a valid effective baseline, got {error}"
        ) from error


def _apply_baselines(
    root: Path,
    source: _TrustedTree,
    rev_config: Config,
    config: Config,
    inputs: dict[str, _Input],
    allowed: set[str],
    temporary: Path,
) -> tuple[Config, dict[str, str], dict[str, tuple[str, ...]]]:
    rev_names = _baseline_names(rev_config)
    _baseline_names(config)
    checks: dict[str, Any] = {}
    statuses: dict[str, str] = {}
    ignored_entries: dict[str, tuple[str, ...]] = {}
    for name, check in config.checks.items():
        relative = _check_baseline_name(check, config.root)
        if relative is None:
            checks[name] = check
            continue
        if relative not in rev_names or relative in allowed:
            entries = _required_candidate_entries(
                temporary, root, relative, check
            )
            if relative in rev_names:
                statuses[relative] = _declared_status(inputs[relative], allowed)
        else:
            entries, status, ignored = _merged_baseline(
                temporary, root, source, relative, check, inputs[relative]
            )
            statuses[relative] = status
            ignored_entries[relative] = ignored
        checks[name] = replace(
            check, baseline=root / relative, effective_baseline=tuple(entries)
        )
    return (
        replace(config, root=root, checks=checks),
        statuses,
        ignored_entries,
    )


def _candidate_lock_authorized(
    root: Path, item: _Input, allowed: set[str]
) -> bool:
    return (
        LOCK_NAME in allowed
        and _input_changed(item)
        and (root / LOCK_NAME).is_file()
    )


def _effective_lock(
    root: Path,
    source: _TrustedTree,
    inputs: dict[str, _Input],
    allowed: set[str],
    temporary: Path,
) -> tuple[Path, str]:
    item = inputs[LOCK_NAME]
    if _candidate_lock_authorized(root, item, allowed):
        path = root / LOCK_NAME
        load_tools(path)
        return path, "authorized"
    revision_raw = source.read(LOCK_NAME)
    if revision_raw is None:
        return _default_lock_path(), _declared_status(item, allowed)
    path = temporary / "rev-tools.lock.toml"
    path.write_bytes(revision_raw)
    return path, _declared_status(item, allowed)


def _gate_files(root: Path) -> list[Path]:
    package = root / "quality_gate"
    return [root / "qg.py", *sorted(
        path for path in package.rglob("*")
        if "__pycache__" not in path.relative_to(package).parent.parts
    )]


def _gate_identity(root: Path) -> dict[str, Any]:
    files: dict[str, str] = {}
    for path in _gate_files(root):
        if not path.is_file():
            continue
        try:
            files[path.relative_to(root).as_posix()] = _sha256(
                path.read_bytes()
            )
        except OSError:
            files[path.relative_to(root).as_posix()] = "unreadable"
    encoded = "".join(
        f"{name}\0{digest}\n" for name, digest in sorted(files.items())
    )
    return {
        "digest": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "files": files,
    }


def _tool_digest(tool: Any) -> str | None:
    directory = _tools_dir() / f"{tool.name}-{tool.version}"
    if not directory.is_dir():
        return None
    try:
        return _tool_payload_digest(tool, directory)
    except PayloadError:
        return "invalid"


def _tool_identity(tools: dict[str, Tool]) -> dict[str, Any]:
    return {
        name: {
            "version": tool.version,
            "payload_sha256": _tool_digest(tool),
        }
        for name, tool in tools.items()
    }


def _candidate_identity_sha256(
    root: Path, relative: str
) -> str | None:
    try:
        return _sha256(_candidate_bytes(root, relative))
    except UsageError:
        return "refused"


def _file_identity_sha256(path: Path) -> str | None:
    try:
        return _sha256(_read_regular(path))
    except UsageError:
        return "refused"


def _object_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _effective_identity(trust: Trust) -> dict[str, str | None]:
    inputs = {
        f"policy {POLICY_NAME}": _file_identity_sha256(trust.config.path),
        f"tool lock {LOCK_NAME}": _file_identity_sha256(trust.lock_path),
        "tool pins": _object_sha256(
            {name: asdict(tool) for name, tool in trust.lock_tools.items()}
        ),
    }
    for check in trust.config.checks.values():
        if check.effective_baseline is None:
            continue
        relative = _check_baseline_name(check, trust.root)
        inputs[f"baseline {relative}"] = _object_sha256(
            {
                "check": check.id,
                "metric_version": check.metric_version,
                "entries": [asdict(entry) for entry in check.effective_baseline],
            }
        )
    return inputs


def _tree_protected_identity(
    trust: Trust, scope: set[str]
) -> dict[str, dict[str, str | None]]:
    assert isinstance(trust.reader, _TrustedTree)
    return {
        path: {
            "rev_sha256": _sha256(trust.reader.read(path)),
            "candidate_sha256": _candidate_identity_sha256(trust.root, path),
        }
        for path in sorted(scope)
    }


def _capture_identity(trust: Trust) -> dict[str, Any]:
    scope = _protected_scope(trust.root, trust.reader, trust.rev_config)
    scope |= _baseline_names(trust.config)
    return {
        "revision": trust.revision,
        "protected": _tree_protected_identity(trust, scope),
        "effective_inputs": _effective_identity(trust),
        "tools": _tool_identity(trust.lock_tools),
        "gate": _gate_identity(Path(__file__).resolve().parent.parent),
    }


def _protected_problems(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    old = before.get("protected", {})
    new = after.get("protected", {})
    return [
        f"protected input {name} changed during the run"
        for name in sorted(set(old) | set(new))
        if old.get(name) != new.get(name)
    ]


def _section_problems(
    before: dict[str, Any],
    after: dict[str, Any],
    section: str,
    what: str,
    *,
    files: bool = False,
) -> list[str]:
    old = before.get(section, {})
    new = after.get(section, {})
    if files:
        old = old.get("files", {})
        new = new.get("files", {})
    return [
        f"{what} {name} changed during the run"
        for name in sorted(set(old) | set(new))
        if old.get(name) != new.get(name)
    ]


def _identity_problems(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    protected = _protected_problems(before, after)
    effective = _section_problems(
        before, after, "effective_inputs", "effective input"
    )
    tools = _section_problems(before, after, "tools", "tool payload")
    gate = _section_problems(
        before, after, "gate", "gate file", files=True
    )
    return protected + effective + tools + gate


def _refuse_inside(root: Path) -> None:
    gate_root = Path(__file__).resolve().parent.parent.resolve()
    if gate_root.is_relative_to(root):
        raise UsageError(
            f"--policy-from: the gate program at {gate_root} lies inside "
            f"the candidate root {root}; run a trusted copy of the gate "
            "outside the candidate"
        )


def _rev_policy_bytes(root: Path, source: _TrustedTree) -> bytes:
    policy = source.read(POLICY_NAME)
    if policy is None:
        raise UsageError(
            f"{root}: --policy-from {source.location!r}: expected {POLICY_NAME} "
            "in the trusted source, got missing"
        )
    return policy


def _directory_source(root: Path, value: str) -> _TrustedTree:
    path = Path(value)
    if not path.is_absolute():
        raise UsageError(
            f"{value}: --policy-from: expected an absolute trusted directory"
        )
    resolved = path.resolve()
    if not resolved.is_dir():
        detail = "missing" if not resolved.exists() else "not a directory"
        raise UsageError(
            f"{path}: --policy-from: expected an existing directory, "
            f"got {detail}"
        )
    if resolved.is_relative_to(root):
        raise UsageError(
            f"{path}: --policy-from: the trusted directory lies inside "
            f"the candidate root {root}"
        )
    return _TrustedTree(resolved)


def _prepare_source(
    root: Path,
    source: _TrustedTree,
    temporary: list[tempfile.TemporaryDirectory[str]],
    allowed: list[str],
) -> Trust:
    policy_root = Path(temporary[0].name)
    _materialize(policy_root, root, source, _rev_policy_bytes(root, source))
    rev_config = load_config(policy_root, candidate_root=root)
    inputs = _protected_inputs(root, source, rev_config)
    allowed_paths = {_normalise(path) for path in allowed}
    config, policy_status = _policy_config(
        root, rev_config, inputs, allowed_paths
    )
    config, baseline_statuses, ignored = _apply_baselines(
        root,
        source,
        rev_config,
        config,
        inputs,
        allowed_paths,
        Path(temporary[1].name),
    )
    lock_path, lock_status = _effective_lock(
        root, source, inputs, allowed_paths, Path(temporary[1].name)
    )
    lock_tools = load_tools(lock_path)
    statuses = dict(baseline_statuses)
    statuses[POLICY_NAME] = policy_status
    statuses[LOCK_NAME] = lock_status
    protected = [
        ProtectedInput(
            item.path,
            item.kind,
            item.rev_sha256,
            item.candidate_sha256,
            statuses.get(item.path, _declared_status(item, allowed_paths)),
            ignored.get(item.path, ()),
        )
        for item in inputs.values()
    ]
    trust = Trust(
        root=root,
        revision=source.location,
        config=config,
        rev_config=rev_config,
        protected=protected,
        lock_path=lock_path,
        lock_tools=lock_tools,
        reader=source,
        trusted=source.root,
        temporary=temporary,
    )
    trust.identity_before = _capture_identity(trust)
    return trust


def prepare_trust(root: Path, value: str, allowed: list[str]) -> Trust:
    root = root.resolve()
    _refuse_inside(root)
    source = _directory_source(root, value)
    temporary = [
        tempfile.TemporaryDirectory(prefix="qg-tree-"),
        tempfile.TemporaryDirectory(prefix="qg-merge-"),
    ]
    try:
        return _prepare_source(root, source, temporary, allowed)
    except BaseException:
        for directory in reversed(temporary):
            directory.cleanup()
        raise
