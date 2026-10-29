"""Added worktree lines and the extra judgement for located violations."""
from __future__ import annotations

import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from .files import _git, git_argv
from .policy import GateError, UsageError
from .ratchet import Location
from .runner import run


HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
DIFF_OPTIONS = (
    "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color",
    "--no-relative", "--text", "--diff-algorithm=myers", "--no-indent-heuristic",
)
Changes = dict[str, list[tuple[int, int]] | None]


def _read_git(root: Path, args: list[str], revision: str) -> bytes:
    try:
        return _git(root, args, f"check: --changed-from {revision!r}")
    except GateError as error:
        raise UsageError(str(error)) from error


def resolve_revision(root: Path, revision: str) -> str:
    raw = _read_git(
        root, ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        revision,
    )
    return raw.decode("ascii").strip()


def _base_files(root: Path, revision: str) -> dict[str, tuple[str, str]]:
    data = _read_git(root, ["ls-tree", "-r", "-z", "--full-tree", revision], revision)
    files: dict[str, tuple[str, str]] = {}
    for record in data.split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, _kind, oid = metadata.decode("ascii").split()
            files[name.decode("utf-8", "surrogateescape")] = (mode, oid)
    return files


def _hunks(patch: bytes) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for line in patch.split(b"\n"):
        match = HUNK.match(line)
        if match is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or b"1")
        if count:
            ranges.append((start, start + count - 1))
    return ranges


def _candidate_bytes(path: Path) -> bytes | None:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            return stream.read()
    except OSError as error:
        raise UsageError(f"check: cannot compare {path}: {error}") from error


def _diff_env(directory: Path) -> dict[str, str]:
    env = dict(os.environ)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
        env.pop(name, None)
    env["GIT_CEILING_DIRECTORIES"] = str(directory.parent)
    env["GIT_ATTR_NOSYSTEM"] = "1"
    return env


def _diff_problem(result: Any) -> str | None:
    if result.execution == "completed" and result.returncode in (0, 1):
        return None
    return result.error or result.stderr_text.strip() or result.execution


def _diff_bytes(root: Path, directory: Path, old: bytes, new: bytes, name: str) -> bytes:
    before = directory / "base"
    after = directory / "candidate"
    try:
        before.write_bytes(old)
        after.write_bytes(new)
    except OSError as error:
        raise UsageError(f"check: cannot prepare diff for {name}: {error}") from error
    result = run(
        git_argv(root, "-C", str(directory), "-c", "core.attributesFile=/dev/null",
                 "diff", "--no-index", *DIFF_OPTIONS, "--unified=0", "--",
                 str(before), str(after)),
        env=_diff_env(directory), budget_seconds=600, capture_limit=None,
    )
    detail = _diff_problem(result)
    if detail is not None:
        raise UsageError(f"check: cannot diff {name}: {detail}")
    return result.stdout


def _regular_base(base: tuple[str, str] | None) -> bool:
    return base is not None and base[0] in ("100644", "100755")


def _lone_cr(data: bytes) -> bool:
    return b"\r" in data.replace(b"\r\n", b"")


def _normalized_lines(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _comparison_hunks(
    root: Path, directory: Path, old: bytes, new: bytes, name: str
) -> list[tuple[int, int]]:
    if _lone_cr(old) or _lone_cr(new):
        old, new = _normalized_lines(old), _normalized_lines(new)
        if old == new:
            return [(1, sys.maxsize)]
    return _hunks(_diff_bytes(root, directory, old, new, name))


def _link_bytes(path: Path) -> bytes:
    try:
        return os.fsencode(os.readlink(path))
    except OSError as error:
        raise UsageError(f"check: cannot compare symlink {path}: {error}") from error


def _link_destination(path: Path, root: Path) -> str | None:
    try:
        return path.resolve(strict=True).relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def _collect_link(
    root: Path, name: str, revision: str, base: tuple[str, str] | None,
    changes: Changes, links: dict[str, str | None],
) -> None:
    path = root / name
    if not path.is_symlink():
        return
    if base is None or base[0] != "120000":
        changes[name] = [(1, sys.maxsize)]
    elif _read_git(root, ["cat-file", "blob", base[1]], revision) != _link_bytes(path):
        changes[name] = [(1, sys.maxsize)]
    else:
        links[name] = _link_destination(path, root)


def _add_link_targets(changes: Changes, links: dict[str, str | None], files: list[str]) -> None:
    inventory = set(files)
    for name, target in links.items():
        changes[name] = changes.get(target, []) if target in inventory else None


def _compare_files(
    root: Path, revision: str, files: list[str], directory: Path,
    base_files: dict[str, tuple[str, str]],
) -> Changes:
    changes: Changes = {}
    links: dict[str, str | None] = {}
    for name in files:
        current = _candidate_bytes(root / name)
        if current is None:
            _collect_link(root, name, revision, base_files.get(name), changes, links)
            continue
        base = base_files.get(name)
        if not _regular_base(base):
            changes[name] = [(1, sys.maxsize)]
            continue
        assert base is not None
        old = _read_git(root, ["cat-file", "blob", base[1]], revision)
        if old != current:
            changes[name] = _comparison_hunks(root, directory, old, current, name)
    _add_link_targets(changes, links, files)
    return changes


def changed_lines(
    root: Path, revision: str, files: list[str]
) -> Changes:
    base_files = _base_files(root, revision)
    try:
        with tempfile.TemporaryDirectory(prefix="qg-changes-") as directory:
            return _compare_files(root, revision, files, Path(directory), base_files)
    except OSError as error:
        raise UsageError(f"check: --changed-from {revision!r}: cannot prepare diff: {error}") from error


def location_coverage(adapter: str) -> str:
    from .adapters import adapter_for

    descriptor = adapter_for(adapter)
    return descriptor.location_coverage if descriptor is not None else "none"


def _overlaps(location: Location, changes: Changes) -> bool:
    return any(
        start <= location.end_line and location.start_line <= end
        for start, end in (changes.get(location.path) or ())
    )


def _threshold_violation(finding: Any, result: Any) -> bool:
    if finding.direction == "min":
        return finding.value < finding.threshold
    return finding.value > finding.threshold


def _report_unlocated(result: Any, finding: Any, reason: str = "incomplete locations") -> None:
    if _threshold_violation(finding, result):
        print(f"check: {result.id}: {finding.subject}: not change-scoped ({reason})")


def _comparable(result: Any, finding: Any, changes: Changes) -> bool:
    unknown = any(
        location.path in changes and changes[location.path] is None
        for location in finding.locations
    )
    if not unknown:
        return True
    result.incomplete_locations = True
    _report_unlocated(result, finding, "source target is outside the comparable inventory")
    if finding.on_changed_lines:
        return True
    finding.on_changed_lines = None
    return False


def _changed_violation(result: Any, finding: Any) -> bool:
    return bool(finding.on_changed_lines) and _threshold_violation(finding, result)


def _reject_changed(result: Any, finding: Any) -> None:
    finding.blocking = True
    result.change_scoped_failure = True
    result.satisfied = False
    result.outcome = "fail"
    result.reason = "threshold violation on changed lines"
    print(
        f"check: {result.id}: {finding.subject}: threshold violation on changed lines "
        f"at {finding.location} (baseline cannot cover changed code)",
        file=sys.stderr,
    )


def _mark_finding(result: Any, finding: Any, changes: Changes) -> None:
    finding.change_scope_evaluated = True
    if finding.locations is None:
        _report_unlocated(result, finding)
        return
    finding.on_changed_lines = any(_overlaps(location, changes) for location in finding.locations)
    if not _comparable(result, finding, changes):
        return
    if _changed_violation(result, finding):
        _reject_changed(result, finding)


def _report_scope(result: Any) -> None:
    coverage = location_coverage(result.adapter)
    if coverage == "none":
        print(f"check: {result.id}: not change-scoped (no complete source locations)")
    elif coverage == "partial":
        print(f"check: {result.id}: test counts are not change-scoped")


def apply_changes(results: list[Any], changes: Changes) -> None:
    for result in results:
        _report_scope(result)
        if result.ratchet is not None:
            for finding in result.ratchet.findings:
                _mark_finding(result, finding, changes)
