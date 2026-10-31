"""Run Python tests under coverage and collect their counts and evidence."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import output_patterns, policy
from .coverage_tool import (
    combine_coverage,
    coverage_config_path,
    coverage_config_text,
    registry_dir,
    write_coverage_config,
)
from .policy import (
    CheckDef,
    DEFAULT_TESTS_BUDGET_SECONDS,
    GateError,
    UnsupportedError,
    UsageError,
    _config_error,
    _integer,
)
from .runner import (
    Diagnostics,
    RunResult,
    StepTimeout,
    analysis_step,
    mark_step,
    record_diagnostics,
    run,
)
from .tools import installed_tool


@dataclass(frozen=True)
class PythonTestsSpec:
    run: tuple[str, ...]
    tests_pattern: str
    tests_pattern_re: re.Pattern[str]
    skipped_pattern: str | None
    skipped_pattern_re: re.Pattern[str] | None
    budget_seconds: int


def _parse_python_tests(
    raw: dict[str, Any], path: Path, full_key: str
) -> PythonTestsSpec:
    run = policy._argv_list(raw, "run", path, f"{full_key}.run")
    if not run:
        raise _config_error(
            path, f"{full_key}.run", "a non-empty argument list", "an empty list"
        )
    pattern_text, pattern, skipped_pattern_text, skipped_pattern = output_patterns._test_patterns(
        raw, path, full_key
    )
    if pattern_text is None or pattern is None:
        raise _config_error(
            path,
            f"{full_key}.tests_pattern",
            "a regular expression with one capture group",
            "missing",
        )
    budget = _integer(
        raw,
        "budget_seconds",
        path,
        f"{full_key}.budget_seconds",
        default=DEFAULT_TESTS_BUDGET_SECONDS,
        minimum=1,
    )
    return PythonTestsSpec(
        tuple(run),
        pattern_text,
        pattern,
        skipped_pattern_text,
        skipped_pattern,
        budget,
    )


def coverage_prefix_values(root: Path, data_dir: Path) -> list[str]:
    """The coverage command and QG_PYTHON value before creating its files."""
    tool, installation = installed_tool("coverage")
    runner = Path(__file__).with_name("covrun.py")
    return [
        sys.executable,
        "-I",
        str(runner),
        str(data_dir),
        str(root),
        str(installation),
        tool.version,
        tool.payload_sha256,
        str(coverage_config_path(data_dir)),
        str(registry_dir(data_dir)),
    ]


def coverage_prefix(root: Path, data_dir: Path) -> list[str]:
    """The in-place expansion of {python} and the value exported as QG_PYTHON."""
    write_coverage_config(data_dir, root)
    return coverage_prefix_values(root, data_dir)


def expand_run(run: tuple[str, ...], prefix: list[str]) -> list[str]:
    expanded: list[str] = []
    for argument in run:
        if argument == "{python}":
            expanded.extend(prefix)
        else:
            expanded.append(argument)
    return expanded


def _executed_tests(
    ran: int | None, skipped: int | None
) -> int | None:
    if ran is None or skipped is None:
        return None
    return ran - skipped


_UNITTEST_FAILED_SUMMARY = re.compile(r"^FAILED \((.*)\)$", re.MULTILINE)
_UNITTEST_OK_SUMMARY = re.compile(r"^OK(?: \(.*\))?$", re.MULTILINE)
_UNITTEST_FAILURE_HEADING = re.compile(r"^(?:FAIL|ERROR): (.+)$", re.MULTILINE)
_UNITTEST_FAILURE_COUNT = re.compile(r"^(failures|errors)=([0-9]+)$")


def _unittest_summary(combined: str) -> str | None:
    summaries = _UNITTEST_FAILED_SUMMARY.findall(combined)
    if len(summaries) != 1 or _UNITTEST_OK_SUMMARY.search(combined):
        return None
    return summaries[0]


def _unittest_failure_count(summary: str) -> int | None:
    failed = 0
    for part in summary.split(","):
        match = _UNITTEST_FAILURE_COUNT.match(part.strip())
        if match is not None:
            failed += int(match.group(2))
    return failed or None


def _unittest_failure_name(heading: str) -> str:
    match = re.search(r"\(([^()]+)\)", heading)
    return match.group(1) if match is not None else heading


def _unittest_outcomes(
    combined: str,
) -> tuple[int, tuple[str, ...]] | None:
    summary = _unittest_summary(combined)
    if summary is None:
        return None
    failed = _unittest_failure_count(summary)
    headings = _UNITTEST_FAILURE_HEADING.findall(combined)
    if failed is None or len(headings) != failed:
        return None
    return failed, tuple(_unittest_failure_name(item) for item in headings)


def _counted_test_results(
    ran: int, skipped: int, failed: int, failures: tuple[str, ...]
) -> Any | None:
    from .checks import TestResults

    passed = ran - skipped - failed
    if passed < 0:
        return None
    return TestResults(ran, passed, failed, failures)


def _failed_test_results(
    ran: int | None,
    skipped: int | None,
    executed: int | None,
    combined: str,
) -> Any | None:
    from .checks import TestResults

    if ran is None or skipped is None or executed is None:
        return None
    if executed == 0:
        return TestResults(ran, 0, 0)
    outcomes = _unittest_outcomes(combined)
    if outcomes is None:
        return None
    return _counted_test_results(ran, skipped, *outcomes)


def _tests_summary(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    combined: str,
    diagnostics: Diagnostics,
    deadline: float,
) -> tuple[
    int | None, int | None, str | None, Any | None
]:
    from .checks import _tests_result

    matches, evaluation = output_patterns._pattern_matches(
        output_patterns._command_patterns(spec),
        combined,
        max(0.0, deadline - time.monotonic()),
    )
    if matches is None:
        if evaluation is not None and evaluation.execution == "budget":
            return (
                None,
                None,
                "test summary matching exceeded the remaining budget",
                _tests_result(
                    check,
                    spec,
                    start,
                    prefix,
                    "test summary matching exceeded the remaining budget",
                    execution="budget",
                    diagnostics=diagnostics,
                ),
            )
        return (
            None,
            None,
            "test summary matching failed",
            _tests_result(
                check,
                spec,
                start,
                prefix,
                "test summary matching failed",
                outcome="error",
                execution="error",
                diagnostics=diagnostics,
            ),
        )
    ran, skipped, error = analysis_step(
        "test count analysis", output_patterns.summarize_matches,
        spec, matches.get("tests", []), matches.get("skipped", []),
    )
    return ran, skipped, error, None


def _tests_failure_reason(
    run_result: RunResult,
    ran: int | None,
    skipped: int | None,
    executed: int | None,
) -> str:
    if executed == 0:
        return (
            f"command exited {run_result.returncode} and no test executed: "
            f"{ran} ran, {skipped} skipped; zero tests is not a pass"
        )
    return f"command exited {run_result.returncode}"


def _tests_failed(
    check: CheckDef,
    spec: Any,
    run_result: RunResult,
    diagnostics: Diagnostics,
    combined: str,
    prefix: str,
    start: float,
    deadline: float,
) -> Any:
    from .checks import _tests_result

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline
    )
    if failure is not None:
        return failure
    if count_error is not None and "ambiguous test summary" in count_error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            count_error,
            outcome="unsupported",
            diagnostics=diagnostics,
            combined=combined,
        )
    executed = _executed_tests(ran, skipped)
    test_results = _failed_test_results(ran, skipped, executed, combined)
    return _tests_result(
        check,
        spec,
        start,
        prefix,
        _tests_failure_reason(run_result, ran, skipped, executed),
        diagnostics=diagnostics,
        measurement={"tests": executed} if executed is not None else None,
        test_results=test_results,
        combined=combined,
    )


def _test_environment(python_prefix: list[str]) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("COVERAGE_") and name != "COVERAGE_CORE":
            del environment[name]
    environment["QG_PYTHON"] = json.dumps(python_prefix)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _combine_tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    settings: str,
    data_dir: Path,
    combined_file: Path,
    diagnostics: Diagnostics,
    deadline: float,
) -> Any | None:
    from .checks import _tests_result

    reason = "coverage combination exceeded the remaining budget"
    try:
        analysis_step(
            "coverage combination", combine_coverage,
            data_dir, combined_file, settings, deadline=deadline,
        )
    except StepTimeout:
        return _tests_result(
            check, spec, start, prefix, reason,
            execution="budget", diagnostics=diagnostics,
        )
    except (UnsupportedError, GateError) as error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"coverage combination failed: {error}",
            outcome="unsupported",
            diagnostics=diagnostics,
        )
    return None


def _tests_setup(
    root: Path,
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
) -> tuple[tempfile.TemporaryDirectory, Path, list[str]] | Any:
    from .checks import _tests_result

    temporary = tempfile.TemporaryDirectory(prefix="qg-coverage-")
    data_dir = Path(temporary.name) / "data"
    try:
        data_dir.mkdir()
        python_prefix = analysis_step(
            "coverage setup", coverage_prefix, root, data_dir
        )
    except UnsupportedError as error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            str(error),
            outcome="unsupported",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
        )
    except UsageError as error:
        return _tests_result(
            check, spec, start, prefix, str(error),
            outcome="error", execution="error",
            diagnostics=Diagnostics(error=str(error)),
            configuration_error=True,
        )
    except OSError as error:
        message = f"cannot create coverage data directory: {error}"
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            message,
            outcome="error",
            execution="error",
            diagnostics=Diagnostics(error=message),
        )
    return temporary, data_dir, python_prefix


def _tests_execution_failure(
    check: CheckDef,
    spec: Any,
    run_result: RunResult,
    diagnostics: Diagnostics,
    combined: str,
    prefix: str,
    start: float,
) -> Any | None:
    from .checks import _tests_result

    if run_result.execution == "error":
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            run_result.error or "cannot run command",
            outcome="error",
            execution="error",
            diagnostics=diagnostics,
        )
    if run_result.execution == "budget":
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command exceeded its {spec.budget_seconds} second budget",
            execution="budget",
            diagnostics=diagnostics,
            combined=combined,
        )
    if run_result.execution == "signal":
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command terminated by signal {-run_result.returncode}",
            execution="signal",
            diagnostics=diagnostics,
            combined=combined,
        )
    return None


def _tests_counts(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    combined: str,
    diagnostics: Diagnostics,
    deadline: float,
) -> tuple[tuple[int, int, int] | None, Any | None]:
    from .checks import TestResults, _tests_result

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline
    )
    if failure is not None:
        return None, failure
    if count_error is not None:
        return None, _tests_result(
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
        return None, _tests_result(
            check,
            spec,
            start,
            prefix,
            f"no test executed: {ran} ran, {skipped} skipped; "
            "zero tests is not a pass",
            diagnostics=diagnostics,
            measurement={"tests": 0},
            test_results=TestResults(ran, 0, 0),
            combined=combined,
        )
    return (ran, skipped, executed), None


def _tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    temporary: tempfile.TemporaryDirectory,
    root: Path,
    data_dir: Path,
    ran: int,
    skipped: int,
    executed: int,
    diagnostics: Diagnostics,
    deadline: float,
) -> Any:
    from .checks import (
        TestResults,
        _check_result,
        _tests_result,
    )

    from .coverage_tool import _coverage_config_problem

    settings = coverage_config_text(root)
    problem = analysis_step(
        "coverage configuration validation", _coverage_config_problem,
        data_dir, settings, deadline=deadline,
    )
    if problem is not None:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            problem,
            outcome="error",
            execution="error",
            diagnostics=Diagnostics(error=problem),
            configuration_error=True,
        )
    combined_file = Path(temporary.name) / "combined" / ".coverage"
    config_file = coverage_config_path(data_dir)
    failure = _combine_tests_evidence(
        check,
        spec,
        start,
        prefix,
        settings,
        data_dir,
        combined_file,
        diagnostics,
        deadline,
    )
    if failure is not None:
        return failure
    outcome = _check_result(
        check,
        start,
        "pass",
        budget_seconds=spec.budget_seconds,
        diagnostics=diagnostics,
        measurement={"tests": executed},
        test_results=TestResults(ran, executed, 0),
        tests_ran=ran,
        tests_skipped=skipped,
        evidence_path=combined_file,
        adapter_data={"coverage_config": config_file, "coverage_settings": settings},
        temporary=temporary,
    )
    print(
        f"{prefix}: passed ({executed} tests, "
        f"{outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _run_python_tests(context: Any) -> Any:
    from .checks import CheckResult

    root, check, prefix = context.root, context.check, context.prefix
    spec = check.spec
    start = time.monotonic()
    deadline = start + spec.budget_seconds
    setup = _tests_setup(root, check, spec, start, prefix)
    if isinstance(setup, CheckResult):
        return setup
    temporary, data_dir, python_prefix = setup

    command = expand_run(spec.run, python_prefix)
    environment = _test_environment(python_prefix)
    mark_step("test command")
    run_result = run(
        command,
        cwd=root,
        env=environment,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    diagnostics = run_result.diagnostics()
    record_diagnostics(diagnostics)
    combined = run_result.combined_text
    failure = _tests_execution_failure(
        check, spec, run_result, diagnostics, combined, prefix, start
    )
    if failure is not None:
        return failure
    if run_result.returncode != 0:
        return _tests_failed(
            check,
            spec,
            run_result,
            diagnostics,
            combined,
            prefix,
            start,
            deadline,
        )

    counts, failure = _tests_counts(
        check, spec, start, prefix, combined, diagnostics, deadline
    )
    if failure is not None:
        return failure
    assert counts is not None
    ran, skipped, executed = counts
    return _tests_evidence(
        check,
        spec,
        start,
        prefix,
        temporary,
        root,
        data_dir,
        ran,
        skipped,
        executed,
        diagnostics,
        deadline,
    )
