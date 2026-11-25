"""Source-character lint: reject invisible control characters in source.

The character table rejects C0 controls except TAB, LF and the
contextual form feed and CR, plus DEL, C1 and bidi controls. Form feed
is allowed at the start of a line and CR is allowed in CRLF. If the data
cannot be decoded, scan for ASCII controls and report columns as byte
offsets.
"""
from __future__ import annotations

import bisect
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import DiffBase, _git, _split_nul, _untracked_files, diff_base, read_regular
from .policy import (
    ConfigError,
    GateError,
    _names,
    _optional_boolean,
    _optional_string,
    _scope,
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
_CONTEXT = r"|(?<=[^\n])\x0c|\r(?!\n)"
_REJECTED = re.compile(
    r"[\x00-\x08\x0b\x0e-\x1f\x7f\x80-\x9f\u202a-\u202e\u2066-\u2069]"
    + _CONTEXT
)
_REJECTED_BYTES = re.compile(
    rb"[\x00-\x08\x0b\x0e-\x1f\x7f]" + _CONTEXT.encode()
)


@dataclass(frozen=True)
class SourceCharsSpec:
    scope: str
    base: str
    include_untracked: bool


def _source_chars_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec, _baseline

    _names(raw, "allow", ALLOW_NAMES, path, full_key)
    _names(raw, "deny", DENY_NAMES, path, full_key)
    baseline = _baseline(raw, root, path, full_key)
    spec = SourceCharsSpec(
        _scope(raw, path, full_key, "all"),
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


def _label(code: int) -> str:
    return f"U+{code:04X}"


def _subject(relative: str, name: str) -> str:
    return f"{relative}:{name}"


def _line_starts(text: str | bytes) -> list[int]:
    """The offset of each line, preceded by -1 so line 1 starts there."""
    newline = ord("\n") if isinstance(text, bytes) else "\n"
    return [-1] + [index for index, value in enumerate(text) if value == newline]


def _rejected_findings(
    relative: str, text: str | bytes, pattern: re.Pattern[Any]
) -> list[Finding]:
    """One finding per rejected code point, counting every occurrence."""
    starts = _line_starts(text)
    grouped: dict[int, list[tuple[int, int]]] = {}
    for match in pattern.finditer(text):
        start = match.start()
        value = text[start]
        code = value if isinstance(value, int) else ord(value)
        line = bisect.bisect_left(starts, start)
        grouped.setdefault(code, []).append((line, start - starts[line - 1]))
    return [
        _finding(relative, code, positions)
        for code, positions in grouped.items()
    ]


def _finding(
    relative: str, code: int, positions: list[tuple[int, int]]
) -> Finding:
    label = _label(code)
    occurrences = [
        {"path": relative, "line": line, "column": column, "codepoint": label}
        for line, column in positions
    ]
    first_line, first_column = positions[0]
    return Finding(
        _subject(relative, label),
        len(occurrences),
        f"{relative}:{first_line}:{first_column}",
        measurement={**occurrences[0], "occurrences": occurrences},
        locations=tuple(
            Location(relative, line, line) for line, _column in positions
        ),
    )


def _decode_finding(
    relative: str, data: bytes, error: UnicodeDecodeError
) -> Finding:
    line = data.count(b"\n", 0, error.start) + 1
    column = error.start - data.rfind(b"\n", 0, error.start)
    return Finding(
        _subject(relative, "decode"),
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


def _not_scanned_finding(relative: str) -> Finding:
    """A path the scan never read: there is no line to point at."""
    return Finding(
        _subject(relative, "not-scanned"),
        1,
        relative,
        measurement={"path": relative},
        locations=None,
        kind="not-scanned",
    )


def _file_findings(relative: str, data: bytes) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [
            *_rejected_findings(relative, data, _REJECTED_BYTES),
            _decode_finding(relative, data, error),
        ]
    return _rejected_findings(relative, text, _REJECTED)


def measure_source_chars(root: Path, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for relative in files:
        data = read_regular(root, relative)
        if data is None:
            findings.append(_not_scanned_finding(relative))
        else:
            findings.extend(_file_findings(relative, data))
    findings.sort(key=lambda item: item.subject)
    return findings


def _unscanned(findings: list[Finding]) -> set[str]:
    return {
        finding.location
        for finding in findings
        if finding.kind == "not-scanned"
    }


def _domain_subjects(files: list[str], unscanned: set[str]) -> list[str]:
    """The subjects the scan covered; a file it never read covers only itself.

    A file that was not read cannot prove a character absent, so its
    character subjects stay outside the domain and their baseline entries
    are reported unmeasured and kept instead of resolved.
    """
    subjects: list[str] = []
    for relative in files:
        if relative in unscanned:
            subjects.append(_subject(relative, "not-scanned"))
            continue
        subjects.extend(
            _subject(relative, _label(code)) for code in _SUBJECT_CODES
        )
        subjects.extend(
            (_subject(relative, "decode"), _subject(relative, "not-scanned"))
        )
    return subjects


def _changed_files(root: Path, spec: SourceCharsSpec, base: DiffBase) -> list[str]:
    raw = _git(
        root,
        ["diff", "--name-only", "-z", "--diff-filter=ACMRTUXB",
         base.commit, "--"],
        "source-character change selection",
    )
    names = _split_nul(raw)
    if spec.include_untracked:
        names.extend(_untracked_files(root))
    return list(dict.fromkeys(names))


def _source_chars_measurement(
    context: Any,
) -> tuple[list[str], list[Finding], DiffBase | None]:
    from .checks import _select_files

    spec = context.check.spec
    mark_step("file selection")
    selected = _select_files(
        context.config, context.check, context.files, context.classes
    )[0]
    base = None
    if spec.scope == "changed" and context.selection is None:
        base = diff_base(
            context.root, spec.base,
            resolved=getattr(context, "base_override", None),
        )
        changed = set(_changed_files(context.root, spec, base))
        selected = [relative for relative in selected if relative in changed]
    mark_step("source character scan")
    return selected, measure_source_chars(context.root, selected), base


def _run_source_chars(context: Any) -> Any:
    from .checks import (
        _baseline_entries,
        _configuration_error,
        _finish_ratchet,
        _ratchet_error,
    )

    check = context.check
    start = time.monotonic()
    try:
        selected, findings, base = _source_chars_measurement(context)
    except ConfigError as error:
        return _configuration_error(check, start, context.prefix, error)
    except GateError as error:
        return _ratchet_error(check, start, context.prefix, error)
    mark_step("baseline loading")
    try:
        entries = _baseline_entries(check)
    except GateError as error:
        return _ratchet_error(check, start, context.prefix, error)
    mark_step("source character domain analysis")
    domain = Domain.of_subjects(
        _domain_subjects(selected, _unscanned(findings)),
        "the selected source files and code points",
    )
    result = _finish_ratchet(
        check,
        findings,
        entries,
        context.prefix,
        start,
        domain,
        f"{len(findings)} character subjects within baseline",
    )
    result.measurement = (
        None if base is None else {"base": base.measurement()}
    )
    return result
