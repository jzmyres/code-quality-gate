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


def _noqa_lines(relative: str, source: str) -> list[int]:
    lines: list[int] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            line = _noqa_token_line(token)
            if line is not None:
                lines.append(line)
    except (tokenize.TokenError, SyntaxError) as error:
        raise GateError(f"cannot tokenize {relative}: {error}") from error
    return lines


def _no_cover_lines(source: str) -> list[int]:
    return [
        number
        for number, line in enumerate(source.splitlines(), 1)
        if NO_COVER.search(line)
    ]


def measure_exclusions(relative: str, source: str) -> list[Finding]:
    no_cover = _no_cover_lines(source)
    noqa = _noqa_lines(relative, source)
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
