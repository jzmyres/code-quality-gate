"""Removal symmetry: report tokens a commit removed but tests or docs retain."""
from __future__ import annotations

import fnmatch
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import _git
from .policy import (
    ConfigError,
    GateError,
    _integer,
    _optional_boolean,
    _optional_string,
    _optional_string_list,
    _string,
    _string_list,
)
from .ratchet import Domain, Finding, Location
from .runner import mark_step


if TYPE_CHECKING:
    from .adapters import ParsedSpec


METRIC_VERSION = "removal-symmetry/1"
DEFAULT_MIN_TOKEN_CHARS = 16
TOKEN_KINDS = ("definition", "string")
_PYTHON_DEF = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)")
_PYTHON_CLASS = re.compile(r"^\s*class\s+([A-Za-z_]\w*)")
_PYTHON_ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)")
_ELISP_DEF = re.compile(
    r"\(\s*(?:defun|defsubst|defmacro|cl-defun|defvar|defconst|defcustom)"
    r"\s+([^\s()]+)"
)


@dataclass(frozen=True)
class RemovalSymmetrySpec:
    scope: str
    base: str
    include_untracked: bool
    min_token_chars: int
    token_kinds: tuple[str, ...]
    scan_classes: tuple[str, ...] | None
    exclude_paths: tuple[str, ...]


def _scope(raw: dict[str, Any], path: Path, full_key: str) -> str:
    if "scope" not in raw:
        return "changed"
    scope = _string(raw, "scope", path, f"{full_key}.scope")
    if scope not in ("all", "changed"):
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of all, changed; "
            f"got {scope!r}"
        )
    return scope


def _token_kinds(raw: dict[str, Any], path: Path, full_key: str) -> tuple[str, ...]:
    if "token_kinds" not in raw:
        return TOKEN_KINDS
    values = _string_list(raw, "token_kinds", path, f"{full_key}.token_kinds")
    if set(values) != set(TOKEN_KINDS) or len(values) != len(TOKEN_KINDS):
        raise ConfigError(
            f"{path}: {full_key}.token_kinds: expected exactly "
            f"{', '.join(TOKEN_KINDS)}; got {', '.join(values) or 'nothing'}"
        )
    return TOKEN_KINDS


def _scan_classes(
    raw: dict[str, Any], path: Path, full_key: str
) -> tuple[str, ...] | None:
    if "scan_classes" not in raw:
        return None
    return _string_list(raw, "scan_classes", path, f"{full_key}.scan_classes")


def _removal_symmetry_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec, _baseline

    baseline = _baseline(raw, root, path, full_key)
    spec = RemovalSymmetrySpec(
        _scope(raw, path, full_key),
        _optional_string(raw, "base", "HEAD^", path, full_key),
        _optional_boolean(raw, "include_untracked", True, path, full_key),
        _integer(
            raw,
            "min_token_chars",
            path,
            f"{full_key}.min_token_chars",
            default=DEFAULT_MIN_TOKEN_CHARS,
            minimum=1,
        ),
        _token_kinds(raw, path, full_key),
        _scan_classes(raw, path, full_key),
        _optional_string_list(
            raw, "exclude_paths", path, f"{full_key}.exclude_paths"
        ),
    )
    return ParsedSpec(
        spec,
        METRIC_VERSION,
        ("static",),
        threshold=0,
        baseline=baseline,
    )


def _diff_path(raw: str) -> str | None:
    if raw == "/dev/null":
        return None
    return raw.removeprefix("a/")


def _section_path(lines: list[str]) -> str | None:
    for line in lines:
        if line.startswith("--- "):
            return _diff_path(line[4:])
    return None


def _removed_lines(diff: str) -> Iterator[tuple[str | None, str]]:
    for block in diff.split("\ndiff --git "):
        lines = block.splitlines()
        path = _section_path(lines)
        in_hunk = False
        for line in lines:
            if line.startswith("@@"):
                in_hunk = True
            elif in_hunk and line.startswith("-"):
                yield path, line[1:]


def _string_end(text: str, start: int, delimiter: str) -> int | None:
    index = start
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text.startswith(delimiter, index):
            return index
        index += 1
    return None


def _string_contents(line: str) -> Iterator[str]:
    index = 0
    while index < len(line):
        quote = line[index]
        if quote not in ("'", '"'):
            index += 1
            continue
        delimiter = quote * 3 if line.startswith(quote * 3, index) else quote
        start = index + len(delimiter)
        end = _string_end(line, start, delimiter)
        if end is None:
            index = start
            continue
        yield line[start:end]
        index = end + len(delimiter)


def _definition_tokens(line: str, path: str) -> Iterator[str]:
    if path.endswith(".py"):
        for pattern in (_PYTHON_DEF, _PYTHON_CLASS, _PYTHON_ASSIGN):
            match = pattern.search(line)
            if match is not None:
                yield match.group(1)
    elif path.endswith(".el"):
        yield from _ELISP_DEF.findall(line)


def _line_tokens(
    line: str, path: str, kinds: tuple[str, ...]
) -> Iterator[tuple[str, str]]:
    if "definition" in kinds:
        for token in _definition_tokens(line, path):
            yield "definition", token
    if "string" in kinds:
        for token in _string_contents(line):
            yield "string", token


def _source_allowed(
    path: str | None, allowed: set[str] | None, spec: RemovalSymmetrySpec
) -> bool:
    if path is None or (allowed is not None and path not in allowed):
        return False
    return not any(
        fnmatch.fnmatchcase(path, pattern)
        for pattern in spec.exclude_paths
    )


def _collect_tokens(
    tokens: dict[tuple[str, str], set[str]],
    path: str,
    line: str,
    spec: RemovalSymmetrySpec,
) -> None:
    for kind, token in _line_tokens(line, path, spec.token_kinds):
        if kind == "string" and len(token) < spec.min_token_chars:
            continue
        tokens.setdefault((kind, token), set()).add(path)


def _removed_tokens(
    root: Path, spec: RemovalSymmetrySpec, allowed: set[str] | None
) -> list[tuple[str, str, tuple[str, ...]]]:
    diff = _git(
        root,
        [
            "diff", "--unified=0", "--no-color", "--no-ext-diff",
            spec.base, "--",
        ],
        "removal-symmetry diff",
    )
    tokens: dict[tuple[str, str], set[str]] = {}
    for path, line in _removed_lines(diff.decode("utf-8", "surrogateescape")):
        if _source_allowed(path, allowed, spec):
            _collect_tokens(tokens, path, line, spec)
    return [
        (kind, token, tuple(sorted(paths)))
        for (kind, token), paths in sorted(tokens.items())
    ]


def _baseline_relative(root: Path, baseline: Path | None) -> str | None:
    if baseline is None:
        return None
    try:
        return baseline.relative_to(root).as_posix()
    except ValueError:
        return None


def _untracked_files(root: Path) -> set[str]:
    raw = _git(
        root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        "removal-symmetry untracked selection",
    )
    return {
        name
        for name in raw.decode("utf-8", "surrogateescape").split("\0")
        if name
    }


def _scan_class_names(context: Any, spec: RemovalSymmetrySpec) -> set[str]:
    if spec.scan_classes is None:
        return set(context.config.classes)
    names = set(spec.scan_classes)
    unknown = names - set(context.config.classes)
    if unknown:
        raise GateError(
            "removal-symmetry scan_classes: unknown class "
            f"{', '.join(sorted(unknown))}"
        )
    return names


def _scan_excluded(
    relative: str, baseline: str | None, spec: RemovalSymmetrySpec
) -> bool:
    return relative == baseline or any(
        fnmatch.fnmatchcase(relative, pattern)
        for pattern in spec.exclude_paths
    )


def _selected_scan_files(
    context: Any, spec: RemovalSymmetrySpec, names: set[str]
) -> list[str]:
    baseline = _baseline_relative(context.root, context.check.baseline)
    return sorted(
        relative
        for relative in context.files
        if context.classes.get(relative) in names
        and not _scan_excluded(relative, baseline, spec)
    )


def _scan_files(context: Any, spec: RemovalSymmetrySpec) -> list[str]:
    selected = _selected_scan_files(
        context, spec, _scan_class_names(context, spec)
    )
    if spec.include_untracked:
        return selected
    untracked = _untracked_files(context.root)
    return [relative for relative in selected if relative not in untracked]


def _read_files(root: Path, files: list[str]) -> list[tuple[str, str]]:
    contents: list[tuple[str, str]] = []
    for relative in files:
        try:
            data = (root / relative).read_bytes()
            text = data.decode("utf-8")
        except OSError as error:
            raise GateError(f"cannot read {relative}: {error}") from error
        except UnicodeDecodeError as error:
            raise GateError(f"cannot read {relative} as UTF-8: {error}") from error
        contents.append((relative, text))
    return contents


def _definition_starts(token: str, text: str) -> Iterator[int]:
    pattern = re.compile(
        rf"(?<![\w-]){re.escape(token)}(?![\w-])"
    )
    for match in pattern.finditer(text):
        yield match.start()


def _string_starts(token: str, text: str) -> Iterator[int]:
    start = text.find(token)
    while start != -1:
        yield start
        start = text.find(token, start + len(token))


def _occurrences(
    text: str, token: str, kind: str
) -> list[tuple[int, int]]:
    starts = (
        _definition_starts(token, text)
        if kind == "definition"
        else _string_starts(token, text)
    )
    return [
        (text.count("\n", 0, start) + 1, text.count("\n", 0, start + len(token)) + 1)
        for start in starts
    ]


def _finding(
    relative: str,
    token: str,
    kind: str,
    removed_from: tuple[str, ...],
    occurrences: list[tuple[int, int]],
) -> Finding:
    lines = [start for start, _end in occurrences]
    return Finding(
        f"{token}@{relative}",
        len(occurrences),
        f"{relative}:{lines[0]}",
        measurement={
            "token": token,
            "kind": kind,
            "removed_from": list(removed_from),
            "path": relative,
            "line": lines[0],
            "occurrences": [
                {"path": relative, "line": start, "end_line": end}
                for start, end in occurrences
            ],
        },
        locations=tuple(
            Location(relative, start, end) for start, end in occurrences
        ),
    )


def _token_findings(
    contents: list[tuple[str, str]],
    token: str,
    kind: str,
    removed_from: tuple[str, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    for relative, text in contents:
        occurrences = _occurrences(text, token, kind)
        if occurrences:
            findings.append(
                _finding(relative, token, kind, removed_from, occurrences)
            )
    return findings


def measure_removal_symmetry(
    root: Path,
    spec: RemovalSymmetrySpec,
    allowed: set[str] | None,
    contents: list[tuple[str, str]],
) -> tuple[list[tuple[str, str, tuple[str, ...]]], list[Finding]]:
    tokens = _removed_tokens(root, spec, allowed)
    findings = [
        finding
        for kind, token, removed_from in tokens
        for finding in _token_findings(contents, token, kind, removed_from)
    ]
    findings.sort(key=lambda item: item.subject)
    return tokens, findings


def _measurement(
    context: Any,
) -> tuple[list[tuple[str, str, tuple[str, ...]]], list[str], list[Finding]]:
    from .checks import _select_files

    mark_step("file selection")
    selected, _class_names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    spec = context.check.spec
    scan_files = _scan_files(context, spec)
    contents = _read_files(context.root, scan_files)
    allowed = None if spec.scope == "all" else set(selected)
    mark_step("removed-token scan")
    tokens, findings = measure_removal_symmetry(
        context.root, spec, allowed, contents
    )
    return tokens, scan_files, findings


def _domain_subjects(
    tokens: list[tuple[str, str, tuple[str, ...]]], scan_files: list[str]
) -> list[str]:
    return [
        f"{token}@{relative}"
        for _kind, token, _removed_from in tokens
        for relative in scan_files
    ]


def _removal_symmetry_ratchet(
    check: Any,
    tokens: list[tuple[str, str, tuple[str, ...]]],
    scan_files: list[str],
    findings: list[Finding],
    entries: list[Any],
    prefix: str,
    start: float,
) -> Any:
    from .checks import _finish_ratchet

    mark_step("removal-symmetry domain analysis")
    domain = Domain.of_subjects(
        _domain_subjects(tokens, scan_files),
        "the removed tokens and selected scan files",
    )
    return _finish_ratchet(
        check, findings, entries, prefix, start, domain, "removed-token"
    )


def _configuration_error(
    check: Any, start: float, prefix: str, error: Exception
) -> Any:
    from .checks import _ratchet_error

    result = _ratchet_error(check, start, prefix, error)
    result.configuration_error = True
    return result


def _run_removal_symmetry(context: Any) -> Any:
    from .checks import _baseline_entries, _ratchet_error

    check = context.check
    start = time.monotonic()
    try:
        tokens, scan_files, findings = _measurement(context)
    except GateError as error:
        return _configuration_error(check, start, context.prefix, error)
    mark_step("baseline loading")
    try:
        entries = _baseline_entries(check)
    except GateError as error:
        return _ratchet_error(check, start, context.prefix, error)
    return _removal_symmetry_ratchet(
        check, tokens, scan_files, findings, entries, context.prefix, start
    )
