"""The verification-loss adapter: test counts, coverage pragmas and noqa."""
from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from .coverage_tool import PRAGMA_NO_COVER
from .policy import GateError
from .ratchet import Finding, Location


NO_COVER = re.compile(PRAGMA_NO_COVER)
NOQA = re.compile(r"#\s*noqa\b", re.IGNORECASE)
FILE_NOQA = re.compile(
    r"#\s*(?:ruff|flake8)\s*:\s*(?i:noqa)"
    r"(?:\s*:\s*[A-Z]+[0-9]+(?:[\s,]+[A-Z]+[0-9]+)*"
    r"|(?=$|#|\s+(?:$|[^\s:])))"
)
FLAKE8_FILE_NOQA = re.compile(r"# flake8[:=]\s*noqa", re.IGNORECASE)
FILE_IGNORE = re.compile(
    r"#\s*ruff\s*:\s*file-ignore\s*\[\s*"
    r"[A-Za-z][A-Za-z0-9-]*(?:\s*,\s*[A-Za-z][A-Za-z0-9-]*)*\s*,?\s*\]"
)
ISORT_FILE_SKIP = re.compile(r"isort: ?skip_file")


def _location(relative: str, lines: list[int]) -> str:
    if not lines:
        return relative
    return f"{relative}:{lines[0]}"


def _noqa_token_line(token: tokenize.TokenInfo) -> int | None:
    if token.type != tokenize.COMMENT:
        return None
    if NOQA.search(token.string) is None:
        return None
    return token.start[0]


def _file_noqa_matches(comment: str) -> list[re.Match[str]]:
    ruff = FILE_NOQA.search(comment)
    flake8 = FLAKE8_FILE_NOQA.match(comment)
    matches = [ruff] if ruff is not None else []
    if flake8 is not None and (ruff is None or flake8.start() != ruff.start()):
        matches.insert(0, flake8)
    return matches


def _file_suppression_matches(token: tokenize.TokenInfo) -> list[re.Match[str]]:
    matches = list(ISORT_FILE_SKIP.finditer(token.string))
    if token.line[:token.start[1]].strip():
        return matches
    matches.extend(_file_noqa_matches(token.string))
    if token.start[1] == 0:
        file_ignore = FILE_IGNORE.match(token.string)
        if file_ignore is not None:
            matches.append(file_ignore)
    return sorted(matches, key=lambda match: match.start())


def _file_suppressions(token: tokenize.TokenInfo) -> list[tuple[int, str]]:
    if token.type != tokenize.COMMENT:
        return []
    return [(token.start[0], match.group()) for match in _file_suppression_matches(token)]


def _noqa_lines(
    relative: str, source: str
) -> tuple[list[int], list[tuple[int, str]]]:
    lines: list[int] = []
    file_suppressions: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            line = _noqa_token_line(token)
            if line is not None:
                lines.append(line)
            file_suppressions.extend(_file_suppressions(token))
    except (tokenize.TokenError, SyntaxError) as error:
        raise GateError(f"cannot tokenize {relative}: {error}") from error
    return lines, file_suppressions


def _no_cover_lines(source: str) -> list[int]:
    return [
        number
        for number, line in enumerate(source.splitlines(), 1)
        if NO_COVER.search(line)
    ]


def _file_suppression_location(relative: str, directives: list[tuple[int, str]]) -> str:
    if not directives:
        return relative
    line, directive = directives[0]
    return f"{relative}:{line} ({directive})"


def measure_exclusions(relative: str, source: str) -> list[Finding]:
    no_cover = _no_cover_lines(source)
    noqa, file_suppressions = _noqa_lines(relative, source)
    return [
        Finding(
            f"exclusions:{relative}:no-cover",
            len(no_cover),
            _location(relative, no_cover),
            locations=tuple(Location(relative, line, line) for line in no_cover),
        ),
        Finding(
            f"exclusions:{relative}:noqa",
            len(noqa),
            _location(relative, noqa),
            locations=tuple(Location(relative, line, line) for line in noqa),
        ),
        Finding(
            f"exclusions:{relative}:file-suppression",
            len(file_suppressions),
            _file_suppression_location(relative, file_suppressions),
            locations=tuple(
                Location(relative, line, line) for line, _ in file_suppressions
            ),
        ),
    ]


def test_findings(
    check_id: str, ran: int, skipped: int
) -> list[Finding]:
    location = f"test summary {check_id}"
    return [
        Finding(
            f"tests:{check_id}:executed",
            ran - skipped,
            location,
        ),
        Finding(
            f"tests:{check_id}:skipped",
            skipped,
            location,
        ),
    ]


def measure_verification(
    root: Path,
    files: list[str],
    test_counts: list[tuple[str, int, int]],
) -> list[Finding]:
    findings: list[Finding] = []
    for check_id, ran, skipped in test_counts:
        findings.extend(test_findings(check_id, ran, skipped))
    for relative in files:
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise GateError(f"cannot read {relative}: {error}") from error
        findings.extend(measure_exclusions(relative, source))
    findings.sort(key=lambda item: item.subject)
    return findings
