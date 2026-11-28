"""Run Python tests under coverage and collect their counts and evidence."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import output_patterns, policy, test_shards
from .coverage_tool import (
    combine_coverage,
    coverage_config_path,
    coverage_config_text,
    registry_dir,
    write_coverage_config,
)
from .json_input import load_json
from .policy import (
    CheckDef,
    DEFAULT_TESTS_BUDGET_SECONDS,
    GateError,
    UnsupportedError,
    UsageError,
    _config_error,
    _integer,
)
from .ratchet import FindingResult
from .runner import Diagnostics, RunResult, execution_outcome, mark_step, run
from .test_shards import FIXTURE_OUTCOMES as FIXTURE_OUTCOMES
from .tools import installed_tool


if TYPE_CHECKING:
    from .adapters import ParsedSpec


@dataclass(frozen=True)
class PythonTestsSpec:
    run: tuple[str, ...]
    tests_pattern: str
    tests_pattern_re: re.Pattern[str]
    skipped_pattern: str | None
    skipped_pattern_re: re.Pattern[str] | None
    budget_seconds: int


def _python_tests_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    spec = _parse_python_tests(raw, path, full_key)
    return ParsedSpec(spec, "test-count/1", ("tests",))


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


def _uses_shard_runner(root: Path, command: tuple[str, ...]) -> bool:
    if len(command) < 2 or command[0] != "{python}":
        return False
    try:
        return (root / command[1]).samefile(Path(__file__).with_name("test_shards.py"))
    except OSError:
        return False


def _test_command(
    root: Path, argv: tuple[str, ...], prefix: list[str], data_dir: Path,
) -> tuple[list[str], Path | None]:
    command = expand_run(argv, prefix)
    if not _uses_shard_runner(root, argv):
        return command, None
    report = data_dir / "test-results.json"
    return [*command, "--result-report", str(report)], report


def _read_result_report(path: Path) -> dict:
    try:
        document = load_json(path.read_text(encoding="utf-8"))
        _validate_result_document(document)
    except FileNotFoundError as error:
        raise ValueError(f"{path}: test result report is missing") from error
    except (OSError, ValueError, RecursionError, test_shards.ShardError) as error:
        raise ValueError(f"{path}: invalid test result report: {error}") from error
    return document


def _validate_result_document(document: Any) -> None:
    if not isinstance(document, dict) or set(document) != {"ids", "records", "fixtures"}:
        raise ValueError("expected only the ids, records and fixtures keys")
    ids = document["ids"]
    if not test_shards._valid_ids(ids):
        raise ValueError("expected a discovery ID list of strings")
    test_shards._validate_records(ids, range(len(ids)), document["records"], document["fixtures"])


def _journal_header(line: str) -> dict:
    if not line.endswith("\n"):
        raise ValueError("missing complete discovery header")
    header = load_json(line)
    _validate_journal_header(header)
    return header


def _validate_journal_header(header: Any) -> None:
    _require_discovery_header(header)
    ids = header["ids"]
    if not all(map(test_shards._valid_ids, (ids, header["discovery_errors"]))):
        raise ValueError("expected discovery IDs and errors as lists of strings")
    _validate_discovery_failures(header["discovery_failed"], len(ids))
    if type(header["full"]) not in (str, type(None)):
        raise ValueError("invalid full-run reason")


def _require_discovery_header(header: Any) -> None:
    keys = {"ids", "discovery_failed", "full", "discovery_errors"}
    if not isinstance(header, dict) or set(header) != keys:
        raise ValueError("invalid discovery header")


def _discovery_position(position: Any, size: int) -> bool:
    return type(position) is int and 0 <= position < size


def _validate_discovery_failures(failed: Any, size: int) -> None:
    if not isinstance(failed, list) or not all(_discovery_position(pos, size) for pos in failed):
        raise ValueError(f"invalid discovery failure positions: {failed!r}")
    if failed != sorted(set(failed)):
        raise ValueError(f"invalid discovery failure position order: {failed!r}")


def _read_result_journal(path: Path, *, interrupted: bool) -> tuple[dict, dict, bool]:
    try:
        with path.open(encoding="utf-8") as journal:
            header, events = _read_journal_frames(journal, interrupted)
        valid = _validate_journal_records(header, events)
    except (OSError, ValueError, RecursionError, test_shards.ShardError) as error:
        raise ValueError(f"{path}: invalid unittest result journal: {error}") from error
    return header, events, valid


def _validate_journal_records(header: dict, events: dict) -> bool:
    ids = header["ids"]
    selected = range(len(ids)) if header["full"] is not None else header["discovery_failed"]
    try:
        test_shards._validate_records(
            ids, selected, events["terminal"], events["fixture"],
            complete=bool(events["finished"]), started=events["started"],
        )
    except test_shards.ShardError:
        if not events["error"]:
            raise
        _recover_journal_accounting(ids, selected, events)
        return False
    return True


def _recover_journal_accounting(ids: list, selected: Any, events: dict) -> None:
    """Keep invocation diagnostics when the runner reports a schedule defect."""
    unique = {}
    for record in events["terminal"]:
        unique.setdefault(test_shards._record_position(record), record)
    positions = sorted(unique.keys() & set(selected))
    records = list(map(unique.__getitem__, positions))
    test_shards._validate_records(ids, positions, records, events["fixture"])
    events["terminal"] = records
    if not all(map(test_shards._valid_position, events["started"])):
        raise ValueError("invalid journal start positions")


def _read_journal_frames(journal: Any, interrupted: bool) -> tuple[dict, dict]:
    header = _journal_header(journal.readline())
    events = {name: [] for name in ("started", "terminal", "fixture", "error", "finished")}
    for line in journal:
        if interrupted and not line.endswith("\n"):
            break
        _append_journal_frame(events, line)
    return header, events


def _append_journal_frame(events: dict, line: str) -> None:
    event, value = test_shards._decode_journal_frame(line, load_json)
    if event not in events or events["finished"] or events["error"]:
        raise ValueError(f"unexpected journal event: {event!r}")
    _validate_journal_marker(event, value)
    events[event].append(value)


def _validate_journal_marker(event: str, value: Any) -> None:
    if event == "finished" and value is not None:
        raise ValueError(f"invalid finished journal event: {value!r}")
    if event == "error" and not isinstance(value, str):
        raise ValueError(f"invalid error journal event: {value!r}")


def _result_rows(records: list) -> list[dict]:
    return [
        {"position": position, "id": name, "outcome": outcome, "duration_seconds": duration}
        for position, name, outcome, _, duration, _ in records
    ]


def _unittest_findings(records: list, fixtures: list, labels: dict | None = None) -> list[FindingResult]:
    return [
        FindingResult(
            subject=name, value=1, bound=None, threshold=0, baseline_reason=None,
            blocking=True, location="unittest",
        )
        for name in test_shards.failed_subjects(records, fixtures, labels)
    ]


def _result_report(path: Path | None) -> tuple[dict, list[FindingResult], str | None]:
    if path is None:
        return {}, [], None
    try:
        report = _read_result_report(path)
    except ValueError as error:
        return {}, [], str(error)
    return (
        {"test_results": _result_rows(report["records"])},
        _unittest_findings(report["records"], report["fixtures"]),
        None,
    )


def _executed_tests(
    ran: int | None, skipped: int | None
) -> int | None:
    if ran is None or skipped is None:
        return None
    return ran - skipped


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
            reason = "test summary matching exceeded the remaining budget"
            return (
                None,
                None,
                reason,
                _tests_result(
                    check,
                    spec,
                    start,
                    prefix,
                    reason,
                    execution="budget",
                    diagnostics=diagnostics,
                    report=False,
                ),
            )
        reason = "test summary matching failed"
        return (
            None,
            None,
            reason,
            _tests_result(
                check,
                spec,
                start,
                prefix,
                reason,
                outcome="error",
                execution="error",
                diagnostics=diagnostics,
                report=False,
            ),
        )
    mark_step("test count analysis")
    ran, skipped, error = output_patterns.summarize_matches(
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
        check, spec, start, prefix, combined, diagnostics, deadline,
    )
    if failure is not None:
        return failure
    if count_error is not None and "ambiguous test summary" in count_error:
        result = _tests_result(
            check,
            spec,
            start,
            prefix,
            count_error,
            outcome="unsupported",
            diagnostics=diagnostics,
            report=False,
        )
    else:
        executed = _executed_tests(ran, skipped)
        result = _tests_result(
            check,
            spec,
            start,
            prefix,
            _tests_failure_reason(run_result, ran, skipped, executed),
            diagnostics=diagnostics,
            measurement={"tests": executed} if executed is not None else None,
            tests_ran=ran,
            tests_skipped=skipped,
            report=False,
        )
    return result


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
) -> Any | None:
    from .checks import _tests_result

    try:
        mark_step("coverage combination")
        combine_coverage(data_dir, combined_file, settings)
    except (UnsupportedError, GateError) as error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"coverage combination failed: {error}",
            outcome="unsupported",
            diagnostics=diagnostics,
            report=False,
        )
    return None


def _tests_setup(
    root: Path,
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    evidence_dir: Path,
) -> tuple[Path, list[str]] | Any:
    from .checks import _tests_result

    data_dir = evidence_dir / "data"
    try:
        data_dir.mkdir()
        mark_step("coverage setup")
        python_prefix = coverage_prefix(root, data_dir)
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
    return data_dir, python_prefix


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

    outcome = execution_outcome(run_result.execution)
    if outcome.error:
        reason = run_result.error or "cannot run command"
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            reason,
            outcome="error",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
        )
    if outcome.budget:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command exceeded its {spec.budget_seconds} second budget",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
        )
    if outcome.signal:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command terminated by signal {-run_result.returncode}",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
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
    from .checks import _tests_result

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline,
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
            report=False,
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
            tests_ran=ran,
            tests_skipped=skipped,
            report=False,
        )
    return (ran, skipped, executed), None


def _tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    evidence_dir: Path,
    root: Path,
    data_dir: Path,
    ran: int,
    skipped: int,
    executed: int,
    diagnostics: Diagnostics,
) -> Any:
    from .checks import _check_result, _tests_result

    from .coverage_tool import _coverage_config_problem

    settings = coverage_config_text(root)
    mark_step("coverage configuration validation")
    problem = _coverage_config_problem(data_dir, settings)
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
            report=False,
        )
    combined_file = evidence_dir / "combined" / ".coverage"
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
        tests_ran=ran,
        tests_skipped=skipped,
        evidence_path=combined_file,
        adapter_data={"coverage_config": config_file, "coverage_settings": settings},
    )
    print(
        f"{prefix}: passed ({executed} tests, "
        f"{outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _run_python_tests(context: Any) -> Any:
    from .checks import (
        CheckResult,
        _finish_temporary,
        _temporary_reason,
        _temporary_test_directory,
    )

    root, check, prefix = context.root, context.check, context.prefix
    spec = check.spec
    start = time.monotonic()
    deadline = start + spec.budget_seconds
    evidence_dir = context.evidence_dir
    setup = _tests_setup(root, check, spec, start, prefix, evidence_dir)
    if isinstance(setup, CheckResult):
        return setup
    data_dir, python_prefix = setup

    command, result_report = _test_command(root, spec.run, python_prefix, data_dir)
    environment = _test_environment(python_prefix)
    temporary = _temporary_test_directory()
    environment["TMPDIR"] = str(temporary)
    mark_step("test command")
    try:
        run_result = run(
            command,
            cwd=root,
            env=environment,
            budget_seconds=max(0.0, deadline - time.monotonic()),
        )
    finally:
        temporary_paths = _finish_temporary(temporary)
    temporary_reason = _temporary_reason(temporary_paths)

    return _finish_python_tests(
        context, run_result, start, deadline, data_dir, result_report, temporary_reason,
    )


def _finish_python_tests(context: Any, child: RunResult, start: float, deadline: float,
                         data_dir: Path, report: Path | None, temporary_reason: str | None) -> Any:
    from .checks import _finish_test_result

    check, prefix = context.check, context.prefix
    combined = child.combined_text
    failure = _tests_execution_failure(check, check.spec, child, child.diagnostics(), combined, prefix, start)
    if failure is not None:
        return _finish_test_result(failure, temporary_reason, prefix, combined)
    result = _python_result_with_evidence(context, child, start, deadline, data_dir, report, temporary_reason)
    if result.outcome != "pass" or temporary_reason is not None:
        return _finish_test_result(result, temporary_reason, prefix, combined)
    return result


def _python_result_with_evidence(context: Any, child: RunResult, start: float, deadline: float,
                                 data_dir: Path, report: Path | None, temporary_reason: str | None) -> Any:
    fields, findings, report_error = _result_report(report)
    if child.returncode == 0 and findings:
        subjects = ", ".join(finding.subject for finding in findings)
        report_error = f"{report}: command exited 0 with failing unittest evidence: {subjects}"
    reason = temporary_reason or report_error
    result = _completed_python_tests(context, start, deadline, child, data_dir, reason)
    result.report_fields.update(fields)
    result.findings = findings
    _attach_result_report_error(result, child, report, report_error)
    return result


def _attach_result_report_error(result: Any, child: RunResult, report: Path | None,
                                error: str | None) -> None:
    from .checks import _combined_reason, _merge_temporary_reason

    if report is not None and child.returncode and not (result.reason or "").startswith("command exited"):
        result.reason = _combined_reason(f"command exited {child.returncode}", result.reason)
    _merge_temporary_reason(result, error)


def _completed_python_tests(context: Any, start: float, deadline: float, child: RunResult,
                            data_dir: Path, reason: str | None) -> Any:
    from .checks import _check_result

    check, prefix = context.check, context.prefix
    spec = check.spec
    diagnostics = child.diagnostics()
    combined = child.combined_text
    if child.returncode != 0:
        return _tests_failed(check, spec, child, diagnostics, combined, prefix, start, deadline)

    counts, failure = _tests_counts(check, spec, start, prefix, combined, diagnostics, deadline)
    if failure is not None:
        return failure
    assert counts is not None
    ran, skipped, executed = counts
    if reason is not None:
        return _check_result(
            check, start, "pass",
            diagnostics=diagnostics, budget_seconds=spec.budget_seconds,
            measurement={"tests": executed}, tests_ran=ran, tests_skipped=skipped,
        )
    return _tests_evidence(
        check, spec, start, prefix, context.evidence_dir, context.root, data_dir,
        ran, skipped, executed, diagnostics,
    )
