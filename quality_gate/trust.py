"""The trust root: protected inputs, effective inputs and run identity.

With --policy-from REV the gate evaluates the candidate working tree against
the policy, baselines and tool lock stored in REV, refusing to trust a
candidate's copy of an input another program reads or executes.
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
class _PathValue:
    kind: str
    sha256: str | None = None
    commit: str | None = None
    head: str | None = None
    index_commit: str | None = None


@dataclass(frozen=True)
class _GitlinkComparison:
    revision: _PathValue
    candidate: _PathValue

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "rev_kind": self.revision.kind,
            "candidate_kind": self.candidate.kind,
            "rev_commit": self.revision.commit,
            "candidate_commit": self.candidate.commit,
            "candidate_head": self.candidate.head,
        }
        if self.revision.kind == "file":
            document["rev_sha256"] = self.revision.sha256
        if self.candidate.kind == "file":
            document["candidate_sha256"] = self.candidate.sha256
        if self.candidate.index_commit is not None:
            document["candidate_index_commit"] = self.candidate.index_commit
        return document


@dataclass(frozen=True)
class ProtectedInput:
    path: str
    kind: str
    rev_sha256: str | None
    candidate_sha256: str | None
    status: str
    ignored_entries: tuple[str, ...] = ()
    gitlink: _GitlinkComparison | None = None

    def to_json(self) -> dict[str, Any]:
        if self.gitlink is None:
            document: dict[str, Any] = {
                "path": self.path,
                "rev_sha256": self.rev_sha256,
                "candidate_sha256": self.candidate_sha256,
                "status": self.status,
            }
        else:
            document = {"path": self.path, **self.gitlink.to_json(), "status": self.status}
        if self.kind == "baseline":
            document["ignored_entries"] = list(self.ignored_entries)
        return document


def _blocked_paths(protected: list[ProtectedInput]) -> list[str]:
    return [item.path for item in protected if item.status == "blocked"]


def _display_value(value: _PathValue) -> str:
    return value.commit or value.sha256 or "-"


def _report_gitlink(item: ProtectedInput) -> None:
    if item.gitlink is None:
        return
    revision = item.gitlink.revision
    candidate = item.gitlink.candidate
    print(
        f"check: protected input {item.path}: REV {revision.kind} "
        f"{_display_value(revision)}; candidate {candidate.kind} "
        f"{_display_value(candidate)}; "
        f"index {candidate.index_commit or candidate.commit or '-'}; "
        f"HEAD {candidate.head or 'not checked out'}; {item.status}",
        file=sys.stderr,
    )


def _report_gitlinks(protected: list[ProtectedInput]) -> None:
    for item in protected:
        _report_gitlink(item)


@dataclass
class Trust:
    root: Path
    revision: str
    config: Config
    rev_config: Config
    protected: list[ProtectedInput]
    lock_path: Path
    lock_tools: dict[str, Tool]
    temporary: list[tempfile.TemporaryDirectory[str]] = field(
        default_factory=list
    )
    identity_before: dict[str, Any] | None = None
    identity_after: dict[str, Any] | None = None
    identity_after_checks: dict[str, Any] | None = None
    identity_problems: list[str] = field(default_factory=list)
    prune_writes: dict[str, bytes | None] = field(default_factory=dict)

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
            "policy_from": self.revision,
            "protected": [item.to_json() for item in self.protected],
            "identity_before": self.identity_before,
            "identity_after": self.identity_after,
        }

    def before_prune(self) -> str | None:
        """Refuse pruning when a protected input changed during the checks."""
        after = _capture_identity(self)
        self.identity_after_checks = after
        self.identity_problems = _identity_problems(
            self.identity_before or {}, after
        )
        return "; ".join(self.identity_problems) or None

    def record_prune_write(
        self, destination: Path, written: bytes | None
    ) -> None:
        try:
            relative = destination.relative_to(self.root).as_posix()
        except ValueError:
            return
        self.prune_writes[relative] = written

    def report_blocked(self) -> bool:
        blocked = _blocked_paths(self.protected)
        if not blocked:
            return False
        print(
            f"check: blocked: protected input changed without "
            f"--allow-protected: {', '.join(blocked)}",
            file=sys.stderr,
        )
        return True

    def finish(
        self, code: int, document: dict[str, Any], *, report_gitlinks: bool = True
    ) -> tuple[int, dict[str, Any]]:
        after = _capture_identity(self)
        start = self.identity_after_checks or self.identity_before or {}
        problems = list(
            dict.fromkeys(
                [
                    *self.identity_problems,
                    *_identity_problems(start, after, self.prune_writes),
                ]
            )
        )
        self.identity_after = after
        document["schema"] = RESULT_SCHEMA
        document["trust"] = self.to_json()
        if report_gitlinks:
            _report_gitlinks(self.protected)
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
    gitlink: _GitlinkComparison | None = None


def _git(root: Path, args: list[str]) -> RunResult:
    return run(
        git_argv(root, *args),
        budget_seconds=600,
        capture_limit=None,
    )


def _git_detail(result: RunResult) -> str:
    return result.stderr_text.strip() or f"git exited {result.returncode}"


def _refuse_graft(root: Path) -> None:
    result = _git(
        root,
        ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"],
    )
    if result.execution != "completed" or result.returncode != 0:
        raise UsageError(
            f"{root}: --policy-from: cannot locate the git directory: "
            f"{_git_detail(result)}"
        )
    graft = Path(result.stdout_text.strip())
    if os.path.lexists(graft):
        raise UsageError(
            f"{graft}: --policy-from: expected no graft file in the "
            "candidate repository, got a graft that can rewrite the "
            "trusted history"
        )


def _commit(root: Path, revision: str) -> str:
    result = _git(root, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
    if result.execution != "completed":
        raise UsageError(
            f"{root}: --policy-from {revision!r}: expected a commit, got "
            f"git {result.execution}"
        )
    if result.returncode != 0:
        raise UsageError(
            f"{root}: --policy-from {revision!r}: expected a commit, got "
            f"{_git_detail(result)}"
        )
    return result.stdout_text.strip()


def _rev_bytes(root: Path, revision: str, relative: str) -> bytes | None:
    result = _git(root, ["cat-file", "blob", f"{revision}:{relative}"])
    if result.execution != "completed":
        raise UsageError(
            f"{root}: cannot read {relative} at {revision}: "
            f"git {result.execution}"
        )
    return result.stdout if result.returncode == 0 else None


def _tree_files(root: Path, revision: str) -> list[str]:
    result = _git(root, ["ls-tree", "-r", "-z", "--name-only", revision])
    if result.execution != "completed" or result.returncode != 0:
        raise UsageError(
            f"{root}: cannot list {revision}: {_git_detail(result)}"
        )
    return [
        item for item in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if item
    ]


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
    patterns: tuple[str, ...], root: Path, revision: str
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
    names = set(_tree_files(root, revision)) | set(_candidate_files(root))
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
    root: Path, revision: str, config: Config
) -> set[str]:
    paths = {POLICY_NAME, LOCK_NAME} | _baseline_names(config)
    return paths | _expand_protect(config.protect_paths, root, revision)


def _git_entries(root: Path, args: list[str], what: str) -> list[str]:
    result = _git(root, args)
    if result.execution != "completed" or result.returncode != 0:
        raise UsageError(f"{root}: cannot list {what}: {_git_detail(result)}")
    return [
        item for item in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if item
    ]


def _revision_entries(root: Path, revision: str) -> dict[str, tuple[str, str]]:
    records = _git_entries(root, ["ls-tree", "-r", "-t", "-z", revision], revision)
    entries = {}
    for record in records:
        metadata, _tab, path = record.partition("\t")
        mode, _kind, oid = metadata.split()
        entries[path] = (mode, oid)
    return entries


def _index_entries(root: Path) -> dict[str, list[tuple[str, str, str]]]:
    records = _git_entries(root, ["ls-files", "--stage", "-z"], "candidate index")
    entries: dict[str, list[tuple[str, str, str]]] = {}
    for record in records:
        metadata, _tab, path = record.partition("\t")
        mode, oid, stage = metadata.split()
        entries.setdefault(path, []).append((mode, oid, stage))
    return entries


def _index_gitlink(
    root: Path, path: str, entries: list[tuple[str, str, str]]
) -> str | None:
    if any(stage != "0" for _mode, _oid, stage in entries):
        raise UsageError(f"{root / path}: protected input: unresolved index entries")
    return next((oid for mode, oid, _stage in entries if mode == "160000"), None)


def _revision_value(
    root: Path, revision: str, path: str, entry: tuple[str, str] | None
) -> _PathValue:
    if entry is None:
        return _PathValue("missing")
    mode, oid = entry
    if mode == "160000":
        return _PathValue("gitlink", commit=oid)
    if mode == "040000":
        return _PathValue("directory")
    return _PathValue("file", sha256=_sha256(_rev_bytes(root, revision, path)))


def _submodule_git(path: Path, args: list[str], what: str) -> str:
    result = _git(path, args)
    if result.execution != "completed" or result.returncode != 0:
        raise _candidate_error(path, f"an unreadable {what}: {_git_detail(result)}")
    return result.stdout_text.strip()


def _submodule_head(path: Path) -> str:
    top = _submodule_git(path, ["rev-parse", "--show-toplevel"], "submodule")
    if Path(top).resolve() != path:
        raise _candidate_error(path, "a submodule with a different worktree root")
    return _submodule_git(path, ["rev-parse", "--verify", "HEAD^{commit}"], "submodule HEAD")


def _directory_value(path: Path, index_commit: str | None) -> _PathValue:
    if index_commit is None:
        return _PathValue("directory")
    if os.path.lexists(path / ".git"):
        return _PathValue("gitlink", commit=index_commit, head=_submodule_head(path))
    try:
        with os.scandir(path) as entries:
            empty = next(entries, None) is None
    except OSError as error:
        raise _candidate_error(path, str(error)) from error
    if empty:
        return _PathValue("gitlink", commit=index_commit)
    return _PathValue("directory", index_commit=index_commit)


def _candidate_value(root: Path, relative: str, index_commit: str | None) -> _PathValue:
    path = _candidate_path(root, relative)
    mode = _parent_mode(path) if path is not None else None
    if mode is None:
        if index_commit is not None:
            return _PathValue("gitlink", commit=index_commit)
        return _PathValue("missing")
    if stat.S_ISDIR(mode):
        return _directory_value(path, index_commit)
    raw = _read_regular(path)
    return _PathValue("file", sha256=_sha256(raw), index_commit=index_commit)


def _contains_gitlink(
    entry: tuple[str, str] | None, staged: list[tuple[str, str, str]]
) -> bool:
    return (entry is not None and entry[0] == "160000") or any(
        mode == "160000" for mode, _oid, _stage in staged
    )


def _comparison(
    root: Path,
    revision: str,
    path: str,
    tree: dict[str, tuple[str, str]],
    index: dict[str, list[tuple[str, str, str]]],
    *,
    identity: bool = False,
) -> _GitlinkComparison | None:
    entry = tree.get(path)
    staged = index.get(path, [])
    if not _contains_gitlink(entry, staged):
        return None
    rev = _revision_value(root, revision, path, entry)
    try:
        candidate = _candidate_value(root, path, _index_gitlink(root, path, staged))
    except UsageError:
        if not identity:
            raise
        candidate = _PathValue("refused")
    return _GitlinkComparison(rev, candidate)


def _gitlink_changed(comparison: _GitlinkComparison) -> bool:
    revision, candidate = comparison.revision, comparison.candidate
    if revision.kind != candidate.kind or candidate.index_commit is not None:
        return True
    return revision.commit != candidate.commit or (
        candidate.head is not None and candidate.head != candidate.commit
    )


def _protected_inputs(
    root: Path, revision: str, config: Config
) -> dict[str, _Input]:
    baselines = _baseline_names(config)
    tree = _revision_entries(root, revision)
    index = _index_entries(root)
    inputs: dict[str, _Input] = {}
    for path in sorted(_protected_scope(root, revision, config)):
        if path == POLICY_NAME:
            kind = "policy"
        elif path == LOCK_NAME:
            kind = "lock"
        elif path in baselines:
            kind = "baseline"
        else:
            kind = "other"
        comparison = _comparison(root, revision, path, tree, index)
        if comparison is None:
            inputs[path] = _Input(
                path, kind, _sha256(_rev_bytes(root, revision, path)),
                _sha256(_candidate_bytes(root, path)),
            )
        else:
            inputs[path] = _Input(
                path, kind, comparison.revision.sha256,
                comparison.candidate.sha256, comparison,
            )
    return inputs


def _input_changed(item: _Input) -> bool:
    return (
        _gitlink_changed(item.gitlink) if item.gitlink is not None
        else item.rev_sha256 != item.candidate_sha256
    )


def _declared_status(item: _Input, allowed: set[str]) -> str:
    if not _input_changed(item):
        return "unchanged"
    if item.path in allowed:
        return "authorized"
    if item.kind == "other":
        return "blocked"
    return "ignored"


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
    policy_root: Path, root: Path, revision: str, policy: bytes
) -> None:
    (policy_root / POLICY_NAME).write_bytes(policy)
    try:
        data = tomllib.loads(policy.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ConfigError(
            f"{root / POLICY_NAME} at {revision}: expected valid TOML, got "
            f"{error}"
        ) from error
    for name in _policy_baseline_names(data):
        raw = _rev_bytes(root, revision, name)
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
    return rev_config, "ignored"


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
    temporary: Path, root: Path, revision: str, relative: str, check: Any
) -> list[BaselineEntry]:
    raw = _rev_bytes(root, revision, relative)
    if raw is None:
        return []
    try:
        return _entries_from_bytes(temporary, "rev", raw, check)
    except GateError as error:
        raise UsageError(
            f"{relative} at {revision}: expected a valid baseline, got {error}"
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
            f"check: {relative}: candidate baseline ignored: {error}",
            file=sys.stderr,
        )
        return [], True


def _tighter_expiry(
    revision: Any, candidate: Any
) -> Any:
    if candidate is None or (revision is not None and revision <= candidate):
        return revision
    return candidate


def _entry_differs(entry: BaselineEntry, candidate: BaselineEntry) -> bool:
    return (
        entry.bound != candidate.bound
        or entry.reason != candidate.reason
        or entry.expires != candidate.expires
        or entry.extras != candidate.extras
    )


def _ignored_parts(entry: BaselineEntry, chosen: BaselineEntry) -> bool:
    return (
        chosen.reason != entry.reason
        or chosen.extras != entry.extras
        or chosen.expires != _tighter_expiry(entry.expires, chosen.expires)
    )


def _merge_entry(
    entry: BaselineEntry,
    chosen: BaselineEntry,
    direction: str = "max",
) -> tuple[BaselineEntry, bool, bool]:
    expires = _tighter_expiry(entry.expires, chosen.expires)
    bound = tighter_bound(entry.bound, chosen.bound, direction)
    if bound != entry.bound or expires != entry.expires:
        return (
            replace(entry, bound=bound, expires=expires),
            True,
            _ignored_parts(entry, chosen),
        )
    return entry, False, _entry_differs(entry, chosen)


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
    item: _Input, tightened: bool, invalid: bool
) -> str:
    if not _input_changed(item):
        return "unchanged"
    if invalid:
        return "ignored"
    if tightened:
        return "tightened"
    return "ignored"


def _merged_baseline(
    temporary: Path,
    root: Path,
    revision: str,
    relative: str,
    check: Any,
    item: _Input,
) -> tuple[list[BaselineEntry], str, tuple[str, ...]]:
    revision_entries = _rev_entries(
        temporary, root, revision, relative, check
    )
    if item.gitlink is not None and item.gitlink.candidate.kind != "file":
        candidate_entries, invalid = [], True
    else:
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
        _baseline_status(item, tightened, invalid),
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
    revision: str,
    rev_config: Config,
    config: Config,
    inputs: dict[str, _Input],
    allowed: set[str],
    temporary: Path,
) -> tuple[Config, dict[str, str], dict[str, tuple[str, ...]]]:
    rev_names = _baseline_names(rev_config)
    _baseline_names(config)
    checks: dict[str, Any] = {}
    prune_paths: dict[str, Path] = {}
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
                temporary, root, revision, relative, check, inputs[relative]
            )
            statuses[relative] = status
            ignored_entries[relative] = ignored
        checks[name] = replace(
            check, baseline=root / relative, effective_baseline=tuple(entries)
        )
        prune_paths[name] = root / relative
    return (
        replace(config, root=root, checks=checks, prune_paths=prune_paths),
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
    revision: str,
    inputs: dict[str, _Input],
    allowed: set[str],
    temporary: Path,
) -> tuple[Path, str]:
    item = inputs[LOCK_NAME]
    if _candidate_lock_authorized(root, item, allowed):
        path = root / LOCK_NAME
        load_tools(path)
        return path, "authorized"
    revision_raw = _rev_bytes(root, revision, LOCK_NAME)
    if revision_raw is None:
        return _default_lock_path(), _declared_status(item, allowed)
    path = temporary / "rev-tools.lock.toml"
    path.write_bytes(revision_raw)
    return path, _declared_status(item, allowed)


def _gate_files(root: Path) -> list[Path]:
    package = root / "quality_gate"
    return [root / "qg.py", *sorted(package.rglob("*.py")), *sorted(package.rglob("*.el"))]


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


def _capture_identity(trust: Trust) -> dict[str, Any]:
    scope = _protected_scope(trust.root, trust.revision, trust.rev_config)
    scope |= _baseline_names(trust.config)
    tree = _revision_entries(trust.root, trust.revision)
    index = _index_entries(trust.root)
    protected = {}
    for path in sorted(scope):
        comparison = _comparison(
            trust.root, trust.revision, path, tree, index, identity=True
        )
        protected[path] = (
            comparison.to_json() if comparison is not None else {
                "rev_sha256": _sha256(_rev_bytes(trust.root, trust.revision, path)),
                "candidate_sha256": _candidate_identity_sha256(trust.root, path),
            }
        )
    return {
        "revision": trust.revision,
        "protected": protected,
        "effective_inputs": _effective_identity(trust),
        "tools": _tool_identity(trust.lock_tools),
        "gate": _gate_identity(Path(__file__).resolve().parent.parent),
    }


def checked_prune_path(root: Path, destination: Path) -> Path:
    """Refuse a prune write that would leave the candidate."""
    try:
        relative = destination.relative_to(root).as_posix()
    except ValueError:
        raise UsageError(
            f"{destination}: prune: expected a path inside the candidate "
            f"root {root}"
        ) from None
    _candidate_parent(root, relative)
    try:
        mode = destination.lstat().st_mode
    except OSError:
        return destination
    if not stat.S_ISREG(mode):
        raise UsageError(
            f"{destination}: prune: expected a regular file inside the "
            f"candidate, got {_kind_name(mode)}"
        )
    return destination


_UNWRITTEN = object()


def _prune_source_is_file(entry: dict[str, Any]) -> bool:
    return (
        "rev_kind" not in entry
        and "rev_sha256" in entry
        and "candidate_sha256" in entry
    )


def _same_revision_files(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return (
        _prune_source_is_file(old)
        and _prune_source_is_file(new)
        and old.get("rev_sha256") == new.get("rev_sha256")
    )


def _allowed_change(
    old: Any, new: Any, written: Any
) -> bool:
    if written is _UNWRITTEN:
        return old == new
    old_entry = old or {}
    new_entry = new or {}
    return (
        _same_revision_files(old_entry, new_entry)
        and new_entry.get("candidate_sha256") == _sha256(written)
    )


def _protected_problems(
    before: dict[str, Any],
    after: dict[str, Any],
    writes: dict[str, bytes | None],
) -> list[str]:
    old = before.get("protected", {})
    new = after.get("protected", {})
    return [
        f"protected input {name} changed during the run"
        for name in sorted(set(old) | set(new))
        if not _allowed_change(
            old.get(name), new.get(name), writes.get(name, _UNWRITTEN)
        )
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
    writes: dict[str, bytes | None] | None = None,
) -> list[str]:
    allow = writes or {}
    protected = _protected_problems(before, after, allow)
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


def _rev_policy_bytes(root: Path, revision: str) -> bytes:
    policy = _rev_bytes(root, revision, POLICY_NAME)
    if policy is None:
        raise UsageError(
            f"{root}: --policy-from {revision!r}: expected {POLICY_NAME} "
            "in the trusted revision, got missing"
        )
    return policy


def _initial_value(item: _Input | None) -> dict[str, Any] | None:
    if item is None:
        return None
    if item.gitlink is not None:
        return item.gitlink.to_json()
    return {"rev_sha256": item.rev_sha256, "candidate_sha256": item.candidate_sha256}


def _initial_gitlink(item: _Input | None, current: dict[str, Any] | None) -> bool:
    return (item is not None and item.gitlink is not None) or (
        current is not None and "rev_kind" in current
    )


def _check_initial_gitlinks(inputs: dict[str, _Input], identity: dict[str, Any]) -> None:
    protected = identity["protected"]
    for path in sorted(set(inputs) | set(protected)):
        item, current = inputs.get(path), protected.get(path)
        if _initial_gitlink(item, current) and _initial_value(item) != current:
            raise UsageError(f"protected input {path} changed while preparing the run")


def prepare_trust(
    root: Path, revision_text: str, allowed: list[str]
) -> Trust:
    root = root.resolve()
    _refuse_inside(root)
    _refuse_graft(root)
    revision = _commit(root, revision_text)
    revision_dir = tempfile.TemporaryDirectory(prefix="qg-rev-")
    merge_dir = tempfile.TemporaryDirectory(prefix="qg-merge-")
    temporary = [revision_dir, merge_dir]
    policy_root = Path(revision_dir.name)
    _materialize(
        policy_root, root, revision, _rev_policy_bytes(root, revision)
    )
    rev_config = load_config(policy_root, candidate_root=root)
    inputs = _protected_inputs(root, revision, rev_config)
    allowed_paths = {_normalise(path) for path in allowed}
    config, policy_status = _policy_config(
        root, rev_config, inputs, allowed_paths
    )
    config, baseline_statuses, ignored = _apply_baselines(
        root,
        revision,
        rev_config,
        config,
        inputs,
        allowed_paths,
        Path(merge_dir.name),
    )
    lock_path, lock_status = _effective_lock(
        root, revision, inputs, allowed_paths, Path(merge_dir.name)
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
            item.gitlink,
        )
        for item in inputs.values()
    ]
    trust = Trust(
        root=root,
        revision=revision,
        config=config,
        rev_config=rev_config,
        protected=protected,
        lock_path=lock_path,
        lock_tools=lock_tools,
        temporary=temporary,
    )
    trust.identity_before = _capture_identity(trust)
    try:
        _check_initial_gitlinks(inputs, trust.identity_before)
    except UsageError:
        trust.close()
        raise
    return trust
