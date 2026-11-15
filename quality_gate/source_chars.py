"""Source-character lint: reject invisible control characters in source."""
from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import _git
from .policy import (
    ConfigError,
    GateError,
    _optional_boolean,
    _optional_string,
    _string,
    _string_list,
)
from .ratchet import Domain, Finding, Location
from .runner import mark_step


if TYPE_CHECKING:
    from .adapters import ParsedSpec


METRIC_VERSION = "source-chars/1"
ALLOW_NAMES = ("tab", "lf", "crlf", "form-feed-at-line-start")
DENY_NAMES = ("nul", "bare-cr", "esc", "del", "c1", "bidi")
_SUBJECT_CODES = (
    tuple(range(0x20))
    + (0x7F,)
    + tuple(range(0x80, 0xA0))
    + tuple(range(0x202A, 0x202F))
    + tuple(range(0x2066, 0x206A))
)


@dataclass(frozen=True)
class SourceCharsSpec:
    scope: str
    base: str
    include_untracked: bool


def _scope(raw: dict[str, Any], path: Path, full_key: str) -> str:
    if "scope" not in raw:
        return "all"
    scope = _string(raw, "scope", path, f"{full_key}.scope")
    if scope not in ("all", "changed"):
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of all, changed; "
            f"got {scope!r}"
        )
    return scope


def _names(
    raw: dict[str, Any],
    key: str,
    expected: tuple[str, ...],
    path: Path,
    full_key: str,
) -> None:
    if key not in raw:
        return
    values = _string_list(raw, key, path, f"{full_key}.{key}")
    if set(values) != set(expected) or len(values) != len(expected):
        raise ConfigError(
            f"{path}: {full_key}.{key}: expected exactly "
            f"{', '.join(expected)}; got {', '.join(values) or 'nothing'}"
        )


def _source_chars_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec, _baseline

    _names(raw, "allow", ALLOW_NAMES, path, full_key)
    _names(raw, "deny", DENY_NAMES, path, full_key)
    baseline = _baseline(raw, root, path, full_key)
    spec = SourceCharsSpec(
        _scope(raw, path, full_key),
        _optional_string(raw, "base", "HEAD^", path, full_key),
        _optional_boolean(raw, "include_untracked", True, path, full_key),
    )
    return ParsedSpec(
        spec,
        METRIC_VERSION,
        ("static",),
        threshold=0,
        baseline=baseline,
    )


def _line_break_length(codes: list[int], index: int) -> int:
    code = codes[index]
    if code == 0x0A:
        return 1
    if code == 0x0D and index + 1 < len(codes) and codes[index + 1] == 0x0A:
        return 2
    return 0


def _positions(codes: list[int]) -> Iterator[tuple[int, int, int]]:
    line = 1
    column = 1
    index = 0
    while index < len(codes):
        length = _line_break_length(codes, index)
        if length:
            index += length
            line += 1
            column = 1
            continue
        yield line, column, codes[index]
        index += 1
        column += 1


def _other_control(code: int) -> bool:
    if code < 0x20:
        return True
    if code == 0x7F:
        return True
    if 0x80 <= code <= 0x9F:
        return True
    return 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069


def _rejected(code: int, column: int) -> bool:
    if code == 0x0C:
        return column != 1
    if code == 0x09:
        return False
    return _other_control(code)


def _control_positions(codes: list[int]) -> Iterator[tuple[int, int, int]]:
    for line, column, code in _positions(codes):
        if _rejected(code, column):
            yield line, column, code


def _ascii_control(code: int) -> bool:
    return code < 0x20 or code == 0x7F


def _byte_control_positions(codes: list[int]) -> Iterator[tuple[int, int, int]]:
    for line, column, code in _positions(codes):
        if _ascii_control(code) and _rejected(code, column):
            yield line, column, code


def _label(code: int) -> str:
    return f"U+{code:04X}"


def _occurrence(
    relative: str, line: int, column: int, label: str
) -> dict[str, Any]:
    return {
        "path": relative,
        "line": line,
        "column": column,
        "codepoint": label,
    }


def _finding(
    relative: str, code: int, positions: list[tuple[int, int]]
) -> Finding:
    label = _label(code)
    first_line, first_column = positions[0]
    occurrences = [
        _occurrence(relative, line, column, label)
        for line, column in positions
    ]
    return Finding(
        f"{relative}:{label}",
        len(positions),
        f"{relative}:{first_line}:{first_column}",
        measurement={
            "path": relative,
            "line": first_line,
            "column": first_column,
            "codepoint": label,
            "occurrences": occurrences,
        },
        locations=tuple(
            Location(relative, line, line) for line, _column in positions
        ),
    )


def _group_findings(
    relative: str, positions: Iterator[tuple[int, int, int]]
) -> list[Finding]:
    grouped: dict[int, list[tuple[int, int]]] = {}
    for line, column, code in positions:
        grouped.setdefault(code, []).append((line, column))
    return [
        _finding(relative, code, occurrences)
        for code, occurrences in grouped.items()
    ]


def _control_findings(relative: str, codes: list[int]) -> list[Finding]:
    return _group_findings(relative, _control_positions(codes))


def _decode_finding(
    relative: str, data: bytes, error: UnicodeDecodeError
) -> Finding:
    prefix = data[: error.start]
    line = prefix.count(b"\n") + 1
    column = error.start - prefix.rfind(b"\n")
    return Finding(
        f"{relative}:decode",
        1,
        f"{relative}:byte {error.start}",
        measurement={
            "path": relative,
            "byte_offset": error.start,
            "line": line,
            "column": column,
        },
        locations=(Location(relative, line, line),),
        kind="decode",
    )


def _decode_findings(
    relative: str, data: bytes, error: UnicodeDecodeError
) -> list[Finding]:
    findings = _group_findings(
        relative, _byte_control_positions(list(data))
    )
    findings.append(_decode_finding(relative, data, error))
    return findings


def _file_findings(relative: str, data: bytes) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return _decode_findings(relative, data, error)
    return _control_findings(relative, [ord(character) for character in text])


def measure_source_chars(root: Path, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for relative in files:
        try:
            data = (root / relative).read_bytes()
        except OSError as error:
            raise GateError(f"cannot read {relative}: {error}") from error
        findings.extend(_file_findings(relative, data))
    findings.sort(key=lambda item: item.subject)
    return findings


def _domain_subjects(files: list[str]) -> list[str]:
    subjects: list[str] = []
    for relative in files:
        subjects.extend(
            f"{relative}:U+{code:04X}" for code in _SUBJECT_CODES
        )
        subjects.append(f"{relative}:decode")
    return subjects


def _split_nul(raw: bytes) -> list[str]:
    return [
        name
        for name in raw.decode("utf-8", "surrogateescape").split("\0")
        if name
    ]


def _changed_files(root: Path, spec: SourceCharsSpec) -> list[str]:
    raw = _git(
        root,
        ["diff", "--name-only", "-z", "--diff-filter=ACMRTUXB",
         spec.base, "--"],
        "source-character change selection",
    )
    names = _split_nul(raw)
    if spec.include_untracked:
        untracked = _git(
            root,
            ["ls-files", "--others", "--exclude-standard", "-z"],
            "source-character untracked selection",
        )
        names.extend(_split_nul(untracked))
    return list(dict.fromkeys(names))


def _source_chars_measurement(context: Any) -> tuple[list[str], list[Finding]]:
    from .checks import _select_files

    mark_step("file selection")
    selected, _class_names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    spec = context.check.spec
    if spec.scope == "changed":
        changed = set(_changed_files(context.root, spec))
        selected = [relative for relative in selected if relative in changed]
    mark_step("source character scan")
    return selected, measure_source_chars(context.root, selected)


def _source_chars_ratchet(
    check: Any,
    findings: list[Finding],
    entries: list[Any],
    selected: list[str],
    prefix: str,
    start: float,
) -> Any:
    from .checks import _finish_ratchet

    mark_step("source character domain analysis")
    domain = Domain.of_subjects(
        _domain_subjects(selected),
        "the selected source files and code points",
    )
    return _finish_ratchet(
        check, findings, entries, prefix, start, domain, "character"
    )


def _run_source_chars(context: Any) -> Any:
    from .checks import _baseline_entries, _ratchet_error

    check = context.check
    start = time.monotonic()
    try:
        selected, findings = _source_chars_measurement(context)
    except GateError as error:
        return _ratchet_error(check, start, context.prefix, error)
    mark_step("baseline loading")
    try:
        entries = _baseline_entries(check)
    except GateError as error:
        return _ratchet_error(check, start, context.prefix, error)
    return _source_chars_ratchet(
        check, findings, entries, selected, context.prefix, start
    )
