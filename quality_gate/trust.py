"""The trust root: protected inputs, effective inputs and run identity.

With --policy-from REV the gate evaluates the candidate working tree against
the policy, baselines and tool lock stored in REV, refusing to trust a
candidate's copy of an input another program reads or executes.
"""
from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from . import tools as tools_module
from .policy import Config, ConfigError, GateError, UsageError, load_config
from .ratchet import BaselineEntry, load_baseline, write_baseline
from .runner import RunResult, run
from .tools import _default_lock_path, _tools_dir, load_tools, payload_digest

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


@dataclass
class Trust:
    root: Path
    revision: str
    config: Config
    protected: list[ProtectedInput]
    lock_path: Path
    temporary: list[tempfile.TemporaryDirectory[str]] = field(
        default_factory=list
    )
    identity_before: dict[str, Any] | None = None
    identity_after: dict[str, Any] | None = None

    def activate(self):
        return tools_module.lock_override(self.lock_path)

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

    def finish(
        self, code: int, document: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        after = _capture_identity(self)
        exempt = _prune_exemption(self.config, document)
        problems = _identity_problems(
            self.identity_before or {}, after, exempt
        )
        self.identity_after = after
        document["schema"] = RESULT_SCHEMA
        document["trust"] = self.to_json()
        if problems:
            message = "; ".join(problems)
            print(f"check: error: {message}", file=sys.stderr)
            document["decision"] = "error"
            document["error"] = message
            return 2, document
        blocked = [item.path for item in self.protected if item.status == "blocked"]
        if blocked:
            print(
                f"check: blocked: protected input changed without "
                f"--allow-protected: {', '.join(blocked)}",
                file=sys.stderr,
            )
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
        ["git", "-c", f"safe.directory={root}", "-C", str(root), *args],
        budget_seconds=600,
        capture_limit=None,
    )


def _git_detail(result: RunResult) -> str:
    return result.stderr_text.strip() or f"git exited {result.returncode}"


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
    result = _git(root, ["cat-file", "-p", f"{revision}:{relative}"])
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
    result = _git(
        root, ["ls-files", "-z", "-c", "-o", "--exclude-standard"]
    )
    if result.execution != "completed" or result.returncode != 0:
        raise UsageError(
            f"{root}: cannot list the candidate: {_git_detail(result)}"
        )
    return [
        item for item in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if item
    ]


def _candidate_bytes(root: Path, relative: str) -> bytes | None:
    path = root / relative
    try:
        if path.is_file() or path.is_symlink():
            return path.read_bytes()
    except OSError:
        return None
    return None


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


def _protected_inputs(
    root: Path, revision: str, config: Config
) -> dict[str, _Input]:
    baselines = _baseline_names(config)
    paths = {POLICY_NAME, LOCK_NAME} | baselines
    paths |= _expand_protect(config.protect_paths, root, revision)
    inputs: dict[str, _Input] = {}
    for path in sorted(paths):
        if path == POLICY_NAME:
            kind = "policy"
        elif path == LOCK_NAME:
            kind = "lock"
        elif path in baselines:
            kind = "baseline"
        else:
            kind = "other"
        inputs[path] = _Input(
            path,
            kind,
            _sha256(_rev_bytes(root, revision, path)),
            _sha256(_candidate_bytes(root, path)),
        )
    return inputs


def _declared_status(item: _Input, allowed: set[str]) -> str:
    if item.rev_sha256 == item.candidate_sha256:
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
    if item.rev_sha256 == item.candidate_sha256:
        return rev_config, "unchanged"
    if POLICY_NAME in allowed:
        return load_config(root), "authorized"
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
    extras = ("files",) if check.adapter == "clones" else ()
    return load_baseline(
        path,
        check_id=check.id,
        metric_version=check.metric_version,
        allowed_extras=extras,
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
    entry: BaselineEntry, chosen: BaselineEntry
) -> tuple[BaselineEntry, bool, bool]:
    expires = _tighter_expiry(entry.expires, chosen.expires)
    if chosen.bound < entry.bound or expires != entry.expires:
        return (
            replace(
                entry,
                bound=min(entry.bound, chosen.bound),
                expires=expires,
            ),
            True,
            _ignored_parts(entry, chosen),
        )
    return entry, False, _entry_differs(entry, chosen)


def _merge_entries(
    revision: list[BaselineEntry], candidate: list[BaselineEntry]
) -> tuple[list[BaselineEntry], tuple[str, ...], bool]:
    remaining = {entry.subject: entry for entry in candidate}
    merged: list[BaselineEntry] = []
    ignored: list[str] = []
    tightened = False
    for entry in revision:
        chosen = remaining.pop(entry.subject, None)
        if chosen is None:
            tightened = True
            continue
        merged_entry, entry_tightened, entry_ignored = _merge_entry(
            entry, chosen
        )
        tightened = tightened or entry_tightened
        if entry_ignored:
            ignored.append(entry.subject)
        merged.append(merged_entry)
    ignored.extend(sorted(remaining))
    return merged, tuple(ignored), tightened


def _check_baseline_name(check: Any, config_root: Path) -> str | None:
    if check.baseline is None:
        return None
    try:
        return check.baseline.relative_to(config_root).as_posix()
    except ValueError:
        return None


def _write_merged(
    temporary: Path, entries: list[BaselineEntry], check: Any
) -> Path:
    name = hashlib.sha256(f"merged\0{check.id}".encode()).hexdigest()[:16]
    path = temporary / f"{name}.toml"
    write_baseline(
        path,
        entries,
        check_id=check.id,
        metric_version=check.metric_version,
    )
    return path


def _baseline_status(
    item: _Input, tightened: bool, invalid: bool
) -> str:
    if item.rev_sha256 == item.candidate_sha256:
        return "unchanged"
    if invalid:
        return "ignored"
    if tightened:
        return "tightened"
    return "ignored"


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
    checks: dict[str, Any] = {}
    prune_paths: dict[str, Path] = {}
    statuses: dict[str, str] = {}
    ignored_entries: dict[str, tuple[str, ...]] = {}
    for name, check in config.checks.items():
        relative = _check_baseline_name(check, config.root)
        if relative is None or relative not in rev_names:
            checks[name] = check
            continue
        item = inputs[relative]
        if relative in allowed:
            checks[name] = replace(check, baseline=root / relative)
            statuses[relative] = _declared_status(item, allowed)
            continue
        revision_entries = _rev_entries(
            temporary, root, revision, relative, check
        )
        candidate_entries, invalid = _candidate_entries(
            temporary, root, relative, check
        )
        merged, ignored, tightened = _merge_entries(
            revision_entries, candidate_entries
        )
        checks[name] = replace(
            check, baseline=_write_merged(temporary, merged, check)
        )
        prune_paths[name] = root / relative
        statuses[relative] = _baseline_status(item, tightened, invalid)
        ignored_entries[relative] = ignored
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
        and item.rev_sha256 != item.candidate_sha256
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
    return [root / "qg.py", *sorted(package.rglob("*.py"))]


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
        return payload_digest(directory)
    except GateError:
        return "invalid"


def _tool_identity(lock: Path) -> dict[str, Any]:
    try:
        tools = load_tools(lock)
    except UsageError as error:
        return {"error": str(error)}
    return {
        name: {
            "version": tool.version,
            "payload_sha256": _tool_digest(tool),
        }
        for name, tool in tools.items()
    }


def _capture_identity(trust: Trust) -> dict[str, Any]:
    protected = {
        item.path: {
            "rev_sha256": item.rev_sha256,
            "candidate_sha256": _sha256(
                _candidate_bytes(trust.root, item.path)
            ),
        }
        for item in trust.protected
    }
    return {
        "revision": trust.revision,
        "protected": protected,
        "tools": _tool_identity(trust.lock_path),
        "gate": _gate_identity(Path(__file__).resolve().parent.parent),
    }


def _prune_destination(config: Config, check_id: str) -> str | None:
    check = config.checks.get(check_id)
    if check is None or check.baseline is None:
        return None
    destination = config.prune_paths.get(check_id, check.baseline)
    try:
        return destination.relative_to(config.root).as_posix()
    except ValueError:
        return None


def _prune_exemption(
    config: Config, document: dict[str, Any]
) -> frozenset[str]:
    prune = document.get("prune") or {}
    if not prune.get("performed"):
        return frozenset()
    return frozenset(
        path
        for check_id in prune.get("requested") or []
        if (path := _prune_destination(config, check_id)) is not None
    )


def _section_problems(
    before: dict[str, Any],
    after: dict[str, Any],
    section: str,
    what: str,
    exempt: frozenset[str] = frozenset(),
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
        if name not in exempt and old.get(name) != new.get(name)
    ]


def _identity_problems(
    before: dict[str, Any],
    after: dict[str, Any],
    exempt: frozenset[str] = frozenset(),
) -> list[str]:
    protected = _section_problems(
        before, after, "protected", "protected input", exempt
    )
    tools = _section_problems(before, after, "tools", "tool payload")
    gate = _section_problems(
        before, after, "gate", "gate file", files=True
    )
    return protected + tools + gate


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


def prepare_trust(
    root: Path, revision_text: str, allowed: list[str]
) -> Trust:
    root = root.resolve()
    _refuse_inside(root)
    revision = _commit(root, revision_text)
    revision_dir = tempfile.TemporaryDirectory(prefix="qg-rev-")
    merge_dir = tempfile.TemporaryDirectory(prefix="qg-merge-")
    temporary = [revision_dir, merge_dir]
    policy_root = Path(revision_dir.name)
    _materialize(
        policy_root, root, revision, _rev_policy_bytes(root, revision)
    )
    rev_config = load_config(policy_root)
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
    load_tools(lock_path)
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
        revision=revision,
        config=config,
        protected=protected,
        lock_path=lock_path,
        temporary=temporary,
    )
    trust.identity_before = _capture_identity(trust)
    return trust
