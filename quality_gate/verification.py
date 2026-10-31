"""The verification-loss adapter: test counts, coverage pragmas and noqa."""
from __future__ import annotations

import io
import re
import sys
import time
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .coverage_tool import PRAGMA_NO_COVER
from .policy import CheckDef, Config, GateError
from .ratchet import Domain, Finding, Location
from .runner import Diagnostics, StepTimeout, analysis_step


@dataclass(frozen=True)
class VerificationSpec:
    requires: str | None


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
            kind="exclusion",
        ),
        Finding(
            f"exclusions:{relative}:noqa",
            len(noqa),
            _location(relative, noqa),
            locations=tuple(Location(relative, line, line) for line in noqa),
            kind="exclusion",
        ),
        Finding(
            f"exclusions:{relative}:file-suppression",
            len(file_suppressions),
            _file_suppression_location(relative, file_suppressions),
            locations=tuple(
                Location(relative, line, line) for line, _ in file_suppressions
            ),
            kind="exclusion",
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
            kind="executed",
        ),
        Finding(
            f"tests:{check_id}:skipped",
            skipped,
            location,
            kind="skipped",
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


def _recorded_test_counts(
    result: Any,
) -> tuple[int, int] | None:
    if result.test_results is not None:
        return result.test_results.selected, result.test_results.skipped
    if result.tests_ran is not None and result.tests_skipped is not None:
        return result.tests_ran, result.tests_skipped
    return None


def _missing_test_count(
    identifier: str, result: Any
) -> str | None:
    if _recorded_test_counts(result) is None:
        return (
            f"test counts unreliable: {identifier} recorded no "
            "ran/skipped counts"
        )
    return None


def _count_problem(
    identifier: str, result: Any | None
) -> str | None:
    if result is None:
        return f"test counts unreliable: {identifier} did not run"
    if result.outcome != "pass":
        return f"test counts unreliable: {identifier} did not pass"
    return _missing_test_count(identifier, result)


def _verification_counts(
    check: CheckDef, prior: dict[str, Any]
) -> tuple[list[tuple[str, int, int]] | None, str | None]:
    from .checks import _test_check_dependencies

    identifiers = _test_check_dependencies(check, prior)
    if not identifiers:
        return None, "no test adapter check to measure"
    counts: list[tuple[str, int, int]] = []
    for identifier in identifiers:
        result = prior.get(identifier)
        problem = _count_problem(identifier, result)
        if problem is not None:
            return None, problem
        assert result is not None
        recorded = _recorded_test_counts(result)
        assert recorded is not None
        counts.append((identifier, *recorded))
    return counts, None


def _verification_files(selected: list[str]) -> list[str]:
    return [relative for relative in selected if relative.endswith(".py")]


def _verification_domain(findings: list[Any]) -> Domain:
    return Domain.of_subjects(
        [finding.subject for finding in findings],
        "the measured Python files and test checks",
    )


def _verification_findings(
    root: Path,
    check: CheckDef,
    files: list[str],
    prior: dict[str, Any],
    start: float,
    prefix: str,
) -> Any:
    from .checks import RATCHET_BUDGET_SECONDS, _budget_detail, _ratchet_error, _ratchet_result

    counts, problem = analysis_step("verification test counts", _verification_counts, check, prior)
    if problem is not None:
        print(f"{prefix}: {problem}", file=sys.stderr)
        return _ratchet_result(
            check,
            start,
            "unsupported",
            diagnostics=Diagnostics(error=problem),
            reason=problem,
        )
    assert counts is not None
    try:
        return analysis_step(
            "verification analysis", measure_verification, root, files, counts,
            deadline=start + RATCHET_BUDGET_SECONDS,
        )
    except StepTimeout:
        reason = _budget_detail(
            "verification analysis exceeded the remaining budget", start, RATCHET_BUDGET_SECONDS
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(check, start, "fail", execution="budget", reason=reason)
    except GateError as error:
        return _ratchet_error(check, start, prefix, error)


def _verification_measurement(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prior: dict[str, Any],
    start: float,
    prefix: str,
) -> Any:
    from .checks import _select_files

    selected, _names = analysis_step(
        "file selection", _select_files, config, check, files, classes
    )
    python_files = analysis_step(
        "Python file selection", _verification_files, selected
    )
    return _verification_findings(
        root, check, python_files, prior, start, prefix
    )


def _verification_entries(
    check: CheckDef, start: float, prefix: str
) -> tuple[list[Any] | None, Any | None]:
    from .checks import _baseline_entries, _ratchet_error

    try:
        return (
            analysis_step("baseline loading", _baseline_entries, check),
            None,
        )
    except GateError as error:
        return None, _ratchet_error(check, start, prefix, error)


def _verification_ratchet(
    check: CheckDef,
    findings: list[Any],
    prefix: str,
    start: float,
) -> Any:
    from .checks import _evaluate_ratchet, _ratchet_result

    entries, failure = _verification_entries(check, start, prefix)
    if failure is not None:
        return failure
    assert entries is not None
    ratchet, failure = _evaluate_ratchet(
        findings, entries, check, prefix,
        analysis_step("verification domain analysis", _verification_domain, findings),
    )
    if ratchet is None:
        return _ratchet_result(
            check, start, failure or "error", reason=failure
        )
    result = _ratchet_result(
        check, start, ratchet.outcome, ratchet=ratchet
    )
    if ratchet.satisfied:
        print(
            f"{prefix}: {len(findings)} subjects within baseline",
            flush=True,
        )
    return result


def _run_verification(context: Any) -> Any:
    from .checks import CheckResult

    root, config, check = context.root, context.config, context.check
    selected_files, file_classes = context.files, context.classes
    prefix, prior = context.prefix, context.prior
    start = time.monotonic()
    measured = _verification_measurement(
        root,
        config,
        check,
        selected_files,
        file_classes,
        prior,
        start,
        prefix,
    )
    if isinstance(measured, CheckResult):
        return measured
    return _verification_ratchet(check, measured, prefix, start)
