"""Configure and run command checks, including tool and file expansion."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import output_patterns, policy
from .policy import (
    DEFAULT_BUDGET_SECONDS, CheckDef, UnsupportedError, UsageError, _config_error, _integer, _string,
)
from .runner import Diagnostics, RunResult, analysis_step, mark_step, record_diagnostics, run
from .tools import current_tools, tool_binary


if TYPE_CHECKING:
    from .adapters import ParsedSpec


@dataclass(frozen=True)
class CommandSpec:
    run: tuple[str, ...]
    budget_seconds: int
    must_match: str | None
    must_match_pattern: re.Pattern[str] | None
    tests_pattern: str | None = None
    tests_pattern_re: re.Pattern[str] | None = None
    skipped_pattern: str | None = None
    skipped_pattern_re: re.Pattern[str] | None = None


def _command_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    spec = _parse_command(raw, path, full_key)
    evidence = ("tests",) if spec.tests_pattern is not None else ("static",)
    return ParsedSpec(spec, "command-exit/1", evidence)


def _parse_command(
    raw: dict[str, Any], path: Path, full_key: str
) -> CommandSpec:
    run = policy._argv_list(raw, "run", path, f"{full_key}.run")
    if not run:
        raise _config_error(path, f"{full_key}.run", "a non-empty argument list", "an empty list")
    budget = _integer(
        raw,
        "budget_seconds",
        path,
        f"{full_key}.budget_seconds",
        default=DEFAULT_BUDGET_SECONDS,
        minimum=1,
    )
    must_match: str | None = None
    pattern: re.Pattern[str] | None = None
    if "must_match" in raw:
        must_match = _string(raw, "must_match", path, f"{full_key}.must_match")
        try:
            pattern = re.compile(must_match)
        except re.error as error:
            raise _config_error(
                path,
                f"{full_key}.must_match",
                "a valid regular expression",
                str(error),
            ) from error
    tests_text, tests_re, skipped_text, skipped_re = output_patterns._test_patterns(
        raw, path, full_key
    )
    return CommandSpec(
        tuple(run),
        budget,
        must_match,
        pattern,
        tests_text,
        tests_re,
        skipped_text,
        skipped_re,
    )


def _file_argument(name: str) -> str:
    return f"./{name}" if name.startswith("-") else name


def _expand_run(
    check: CheckDef, files: list[str]
) -> tuple[list[str], str | None]:
    spec = check.spec
    expanded: list[str] = []
    tools = None
    for argument in spec.run:
        if argument == "{files}":
            expanded.extend(map(_file_argument, files))
            continue
        match = re.fullmatch(r"\{tool:([^{}]+)\}", argument)
        if match is None:
            expanded.append(argument)
            continue
        name = match.group(1)
        if tools is None:
            _lock, tools = current_tools()
        if name not in tools:
            known = ", ".join(sorted(tools)) or "none"
            return (
                [],
                f"unknown tool {name!r} (pinned tools: {known}); "
                "run 'python3 -I qg.py tools fetch'",
            )
        try:
            expanded.append(str(tool_binary(name)))
        except UnsupportedError as error:
            return [], str(error)
    return expanded, None


def _command_failure(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    reason: str,
    **fields: Any,
) -> Any:
    from .checks import _tests_result

    return _tests_result(check, spec, start, prefix, reason, **fields)


def _expanded_or_failure(
    check: CheckDef,
    spec: Any,
    selected: list[str],
    prefix: str,
    start: float,
) -> tuple[list[str] | None, Any | None]:
    try:
        expanded, unsupported = analysis_step(
            "command preparation", _expand_run, check, selected
        )
    except UsageError as error:
        return None, _command_failure(
            check,
            spec,
            start,
            prefix,
            str(error),
            outcome="error",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
        )
    if unsupported is not None:
        return None, _command_failure(
            check,
            spec,
            start,
            prefix,
            unsupported,
            outcome="unsupported",
            execution="error",
            diagnostics=Diagnostics(error=unsupported),
        )
    return expanded, None


def _termination_failure(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    result: RunResult,
    diagnostics: Diagnostics,
) -> Any | None:
    combined = result.combined_text
    if result.execution == "error":
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            result.error or "cannot run command",
            outcome="error",
            execution="error",
            diagnostics=diagnostics,
        )
    if result.execution == "budget":
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            f"command exceeded its {spec.budget_seconds} second budget",
            execution="budget",
            diagnostics=diagnostics,
            combined=combined,
        )
    if result.execution == "signal":
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            f"command terminated by signal {-result.returncode}",
            execution="signal",
            diagnostics=diagnostics,
            combined=combined,
        )
    if result.returncode != 0:
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            f"command exited {result.returncode}",
            diagnostics=diagnostics,
            combined=combined,
        )
    return None


def _pattern_failure(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    diagnostics: Diagnostics,
    evaluation: RunResult | None,
) -> Any:
    if evaluation is not None and evaluation.execution == "budget":
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            "output matching exceeded the remaining budget",
            execution="budget",
            diagnostics=diagnostics,
        )
    return _command_failure(
        check,
        spec,
        start,
        prefix,
        "output matching failed",
        outcome="error",
        execution="error",
        diagnostics=diagnostics,
    )


def _command_test_fields(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    matches: dict[str, Any],
    diagnostics: Diagnostics,
    combined: str,
) -> tuple[dict[str, Any], Any | None]:
    if spec.tests_pattern_re is None:
        return {}, None
    ran, skipped, count_error = analysis_step(
        "test count analysis", output_patterns.summarize_matches,
        spec, matches.get("tests", []), matches.get("skipped", []),
    )
    if count_error is not None:
        return {}, _command_failure(
            check,
            spec,
            start,
            prefix,
            count_error,
            outcome="unsupported",
            diagnostics=diagnostics,
            combined=combined,
        )
    assert ran is not None and skipped is not None
    executed = ran - skipped
    if executed == 0:
        return {}, _command_failure(
            check,
            spec,
            start,
            prefix,
            f"no test executed: {ran} ran, {skipped} skipped; "
            "zero tests is not a pass",
            diagnostics=diagnostics,
            measurement={"tests": 0},
            combined=combined,
        )
    return {
        "measurement": {"tests": executed},
        "tests_ran": ran,
        "tests_skipped": skipped,
    }, None


def _command_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    result: RunResult,
    diagnostics: Diagnostics,
    deadline: float,
) -> Any:
    from .checks import _check_result

    combined = result.combined_text
    patterns = output_patterns._command_patterns(spec)
    matches: dict[str, Any] = {}
    if patterns:
        matches, evaluation = output_patterns._pattern_matches(
            patterns,
            combined,
            max(0.0, deadline - time.monotonic()),
        )
        if matches is None:
            return _pattern_failure(
                check, spec, start, prefix, diagnostics, evaluation
            )
    fields, failure = _command_test_fields(
        check, spec, start, prefix, matches, diagnostics, combined
    )
    if failure is not None:
        return failure
    if spec.must_match_pattern is not None and not matches.get("must_match"):
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            f"output did not match must_match {spec.must_match!r}",
            diagnostics=diagnostics,
            combined=combined,
            **fields,
        )
    outcome = _check_result(
        check,
        start,
        "pass",
        budget_seconds=spec.budget_seconds,
        diagnostics=diagnostics,
        **fields,
    )
    print(
        f"{prefix}: passed (exit 0, {outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _run_command(context: Any) -> Any:
    from .checks import _adapter_selection, _class_text

    root, check, prefix = context.root, context.check, context.prefix
    spec, start, selected, names = _adapter_selection(context)
    if "{files}" in spec.run and not selected:
        return _command_failure(
            check,
            spec,
            start,
            prefix,
            f"no files selected (classes: {_class_text(names)}); "
            "zero inputs is not a pass",
        )
    expanded, failure = _expanded_or_failure(
        check, spec, selected, prefix, start
    )
    if failure is not None:
        return failure
    assert expanded is not None
    deadline = start + spec.budget_seconds
    mark_step("command")
    result = run(
        expanded,
        cwd=root,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    diagnostics = result.diagnostics()
    record_diagnostics(diagnostics)
    failure = _termination_failure(
        check, spec, start, prefix, result, diagnostics
    )
    if failure is not None:
        return failure
    return _command_evidence(
        check, spec, start, prefix, result, diagnostics, deadline
    )
