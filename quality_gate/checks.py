"""Check adapters, the check runner and the combined check command."""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import gate_result
from .clones import measure_clones
from .coverage_tool import (
    combine_coverage,
    coverage_config_path,
)
from .files import hygiene_result, validate_inventory
from .policy import (
    CheckDef,
    Config,
    GateError,
    UnsupportedError,
    UsageError,
)
from .python_crap import measure_crap
from .python_tests import (
    coverage_prefix,
    expand_run,
    summarize_matches,
)
from .ratchet import (
    Domain,
    RatchetResult,
    evaluate,
    load_baseline,
    pruned_entries,
    write_baseline,
)
from .runner import Diagnostics, RunResult, run
from .tools import load_tools, tool_binary, _default_lock_path


CLONE_BUDGET_SECONDS = 600
REGEX_RUNNER = Path(__file__).with_name("regexrun.py")


@dataclass
class CheckResult:
    id: str
    kind: str
    tier: int | None
    enforcement: str
    adapter: str
    evidence: tuple[str, ...]
    metric_version: str
    outcome: str
    execution: str
    duration_seconds: float
    budget_seconds: int | None
    findings: list[Any] = field(default_factory=list)
    resolved_baseline_entries: list[str] = field(default_factory=list)
    unmeasured_baseline_entries: list[str] = field(default_factory=list)
    threshold: float | None = None
    baseline_path: Path | None = None
    ratchet: RatchetResult | None = None
    measurement: dict[str, Any] | None = None
    satisfied: bool | None = None
    reason: str | None = None
    diagnostics: Diagnostics = field(default_factory=Diagnostics)
    evidence_path: Path | None = None
    coverage_config: Path | None = None
    temporary: Any = field(default=None, repr=False, compare=False)

    def is_satisfied(self) -> bool:
        if self.satisfied is not None:
            return self.satisfied
        if self.outcome == "pass":
            return True
        return self.kind == "check" and self.enforcement == "advisory"

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "tier": self.tier,
            "enforcement": self.enforcement,
            "adapter": self.adapter,
            "evidence": list(self.evidence),
            "metric_version": self.metric_version,
            "execution": self.execution,
            "outcome": self.outcome,
            "satisfied": self.is_satisfied(),
            "duration_seconds": round(self.duration_seconds, 6),
            "budget_seconds": self.budget_seconds,
            "diagnostics": self.diagnostics.to_json(),
            "findings": [
                item.to_json() if hasattr(item, "to_json") else item
                for item in self.findings
            ],
            "resolved_baseline_entries": list(self.resolved_baseline_entries),
            "unmeasured_baseline_entries": list(self.unmeasured_baseline_entries),
            "reason": self.reason,
        }
        if self.measurement is not None:
            document["measurement"] = self.measurement
        return document


def _select_files(
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
) -> tuple[list[str], list[str]]:
    names = sorted(
        name
        for name, class_def in config.classes.items()
        if check.id in class_def.checks
    )
    selected = sorted(
        relative for relative in files if classes.get(relative) in names
    )
    return selected, names


def _class_text(names: list[str]) -> str:
    return ", ".join(names) or "none"


def _file_argument(name: str) -> str:
    return f"./{name}" if name.startswith("-") else name


def _expand_run(
    check: CheckDef, files: list[str]
) -> tuple[list[str], str | None]:
    assert check.command is not None
    expanded: list[str] = []
    tools = None
    lock = _default_lock_path()
    for argument in check.command.run:
        if argument == "{files}":
            expanded.extend(map(_file_argument, files))
            continue
        match = re.fullmatch(r"\{tool:([^{}]+)\}", argument)
        if match is None:
            expanded.append(argument)
            continue
        name = match.group(1)
        if tools is None:
            tools = load_tools(lock)
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


def _check_result(
    check: CheckDef,
    start: float,
    outcome: str,
    *,
    execution: str = "completed",
    budget_seconds: int | None = None,
    **fields: Any,
) -> CheckResult:
    return CheckResult(
        id=check.id,
        kind="check",
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        evidence=check.evidence,
        metric_version=check.metric_version,
        outcome=outcome,
        execution=execution,
        duration_seconds=time.monotonic() - start,
        budget_seconds=budget_seconds,
        threshold=check.threshold,
        baseline_path=check.baseline,
        **fields,
    )


def _evaluate_ratchet(
    findings: list[Any],
    entries: list[Any],
    check: CheckDef,
    prefix: str,
    domain: Domain,
) -> tuple[RatchetResult | None, str | None]:
    assert check.threshold is not None
    try:
        return (
            evaluate(
                findings,
                entries,
                threshold=check.threshold,
                enforcement=check.enforcement,
                prefix=prefix,
                adapter=check.adapter,
                domain=domain,
            ),
            None,
        )
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, "unsupported"
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, "error"


def _command_failure(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    reason: str,
    **fields: Any,
) -> CheckResult:
    return _tests_result(check, spec, start, prefix, reason, **fields)


def _expanded_or_failure(
    check: CheckDef,
    spec: Any,
    selected: list[str],
    prefix: str,
    start: float,
) -> tuple[list[str] | None, CheckResult | None]:
    try:
        expanded, unsupported = _expand_run(check, selected)
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
) -> CheckResult | None:
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


def _command_patterns(spec: Any) -> dict[str, str]:
    patterns: dict[str, str] = {}
    for name in ("tests", "skipped"):
        value = getattr(spec, f"{name}_pattern", None)
        if value is not None:
            patterns[name] = value
    must_match = getattr(spec, "must_match", None)
    if must_match is not None:
        patterns["must_match"] = must_match
    return patterns


def _pattern_matches(
    patterns: dict[str, str], text: str, budget_seconds: float
) -> tuple[dict[str, Any] | None, RunResult | None]:
    with tempfile.TemporaryDirectory(prefix="qg-regex-") as temporary:
        job = Path(temporary) / "job.json"
        job.write_text(
            json.dumps({"text": text, "patterns": patterns}),
            encoding="utf-8",
        )
        result = run(
            [sys.executable, "-I", str(REGEX_RUNNER), str(job)],
            budget_seconds=budget_seconds,
        )
    if result.execution != "completed" or result.returncode != 0:
        return None, result
    try:
        return json.loads(result.stdout_text), result
    except ValueError:
        return None, result


def _pattern_failure(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    diagnostics: Diagnostics,
    evaluation: RunResult | None,
) -> CheckResult:
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


def _tests_measurement(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    matches: dict[str, Any],
    diagnostics: Diagnostics,
    combined: str,
) -> tuple[dict[str, Any] | None, CheckResult | None]:
    if spec.tests_pattern_re is None:
        return None, None
    ran, skipped, count_error = summarize_matches(
        spec, matches.get("tests", []), matches.get("skipped", [])
    )
    if count_error is not None:
        return None, _command_failure(
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
        return None, _command_failure(
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
    return {"tests": executed}, None


def _command_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    result: RunResult,
    diagnostics: Diagnostics,
    deadline: float,
) -> CheckResult:
    combined = result.combined_text
    patterns = _command_patterns(spec)
    matches: dict[str, Any] = {}
    if patterns:
        matches, evaluation = _pattern_matches(
            patterns,
            combined,
            max(0.0, deadline - time.monotonic()),
        )
        if matches is None:
            return _pattern_failure(
                check, spec, start, prefix, diagnostics, evaluation
            )
    measurement, failure = _tests_measurement(
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
            measurement=measurement,
            combined=combined,
        )
    outcome = _check_result(
        check,
        start,
        "pass",
        budget_seconds=spec.budget_seconds,
        diagnostics=diagnostics,
        measurement=measurement,
    )
    print(
        f"{prefix}: passed (exit 0, {outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _run_command(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prefix: str,
) -> CheckResult:
    assert check.command is not None
    spec = check.command
    start = time.monotonic()
    selected, names = _select_files(config, check, files, classes)
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
    result = run(
        expanded,
        cwd=root,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    diagnostics = result.diagnostics()
    failure = _termination_failure(
        check, spec, start, prefix, result, diagnostics
    )
    if failure is not None:
        return failure
    return _command_evidence(
        check, spec, start, prefix, result, diagnostics, deadline
    )


def _clone_outcome(measurement: Any) -> str:
    if measurement.execution in ("budget", "signal"):
        return "fail"
    return "unsupported" if measurement.unsupported else "error"


def _ratchet_reason(
    ratchet: RatchetResult | None, reason: str | None
) -> str | None:
    if ratchet is None or ratchet.outcome == "pass":
        return reason
    return reason or (
        "ratchet findings did not satisfy the threshold or baseline"
    )


def _ratchet_result(
    check: CheckDef,
    start: float,
    outcome: str,
    *,
    execution: str = "completed",
    ratchet: RatchetResult | None = None,
    measurement: dict[str, Any] | None = None,
    diagnostics: Diagnostics | None = None,
    reason: str | None = None,
) -> CheckResult:
    return _check_result(
        check,
        start,
        outcome,
        execution=execution,
        budget_seconds=CLONE_BUDGET_SECONDS,
        findings=ratchet.findings if ratchet is not None else [],
        resolved_baseline_entries=ratchet.resolved if ratchet is not None else [],
        unmeasured_baseline_entries=(
            ratchet.unmeasured if ratchet is not None else []
        ),
        satisfied=ratchet.satisfied if ratchet is not None else None,
        ratchet=ratchet,
        measurement=measurement,
        diagnostics=diagnostics or Diagnostics(),
        reason=_ratchet_reason(ratchet, reason),
    )


def _clone_result(
    check: CheckDef,
    start: float,
    *,
    outcome: str,
    execution: str = "completed",
    ratchet: RatchetResult | None = None,
    diagnostics: Diagnostics | None = None,
    reason: str | None = None,
) -> CheckResult:
    assert check.clones is not None
    return _ratchet_result(
        check,
        start,
        outcome,
        execution=execution,
        ratchet=ratchet,
        diagnostics=diagnostics,
        reason=reason,
    )


def _print_clone_summary(prefix: str, findings: list[Any]) -> None:
    if findings:
        noun = "clone" if len(findings) == 1 else "clones"
        print(
            f"{prefix}: {len(findings)} {noun} within baseline",
            flush=True,
        )
    else:
        print(f"{prefix}: 0 clones", flush=True)


def _scope_resolves(
    entry: Any, selected: set[str], present: set[str]
) -> bool:
    scope = entry.extras.get("files")
    if not scope:
        return True
    return all(name in selected for name in scope) or any(
        name not in present for name in scope
    )


def _clone_domain(
    entries: list[Any], selected: list[str], files: list[str]
) -> Domain:
    chosen = set(selected)
    present = set(files)
    subjects = [
        entry.subject
        for entry in entries
        if _scope_resolves(entry, chosen, present)
    ]
    return Domain.of_subjects(subjects, "the selected files")


def _run_clones(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prefix: str,
) -> CheckResult:
    assert check.clones is not None
    start = time.monotonic()
    selected, names = _select_files(config, check, files, classes)
    if not selected:
        class_text = _class_text(names)
        print(
            f"{prefix}: no files selected (classes: {class_text}); "
            "zero inputs is not a pass",
            file=sys.stderr,
        )
        return _clone_result(
            check,
            start,
            outcome="fail",
            reason=f"no files selected (classes: {class_text}); "
            "zero inputs is not a pass",
        )
    measurement = measure_clones(
        root,
        selected,
        check.clones.min_tokens,
        config.max_bytes,
    )
    diagnostics = measurement.diagnostics
    if measurement.error is not None:
        print(f"{prefix}: {measurement.error}", file=sys.stderr)
        return _clone_result(
            check,
            start,
            outcome=_clone_outcome(measurement),
            execution=measurement.execution,
            diagnostics=diagnostics,
            reason=measurement.error,
        )
    try:
        entries = load_baseline(
            check.baseline,
            check_id=check.id,
            metric_version=check.metric_version,
            allowed_extras=("files",),
        )
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _clone_result(
            check,
            start,
            outcome="error",
            execution="error",
            diagnostics=diagnostics,
            reason=str(error),
        )
    ratchet, failure = _evaluate_ratchet(
        measurement.findings,
        entries,
        check,
        prefix,
        _clone_domain(entries, selected, files),
    )
    if ratchet is None:
        return _clone_result(
            check,
            start,
            outcome=failure or "error",
            execution="completed",
            diagnostics=diagnostics,
            reason=failure,
        )
    result = _clone_result(
        check,
        start,
        outcome=ratchet.outcome,
        ratchet=ratchet,
        diagnostics=diagnostics,
    )
    if ratchet.satisfied:
        _print_clone_summary(prefix, measurement.findings)
    return result


def _print_output(prefix: str, combined: str) -> None:
    if combined.strip():
        print(combined.rstrip(), file=sys.stderr)


def _executed_tests(
    ran: int | None, skipped: int | None
) -> int | None:
    if ran is None or skipped is None:
        return None
    return ran - skipped


def _tests_result(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    reason: str,
    *,
    outcome: str = "fail",
    execution: str = "completed",
    diagnostics: Diagnostics | None = None,
    measurement: dict[str, Any] | None = None,
    combined: str | None = None,
    **fields: Any,
) -> CheckResult:
    print(f"{prefix}: {reason}", file=sys.stderr)
    if combined is not None:
        _print_output(prefix, combined)
    return _check_result(
        check,
        start,
        outcome,
        execution=execution,
        budget_seconds=spec.budget_seconds,
        diagnostics=diagnostics or Diagnostics(),
        measurement=measurement,
        reason=reason,
        **fields,
    )


def _tests_summary(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    combined: str,
    diagnostics: Diagnostics,
    deadline: float,
) -> tuple[
    int | None, int | None, str | None, CheckResult | None
]:
    matches, evaluation = _pattern_matches(
        _command_patterns(spec),
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
    ran, skipped, error = summarize_matches(
        spec, matches.get("tests", []), matches.get("skipped", [])
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
) -> CheckResult:
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
    return _tests_result(
        check,
        spec,
        start,
        prefix,
        _tests_failure_reason(run_result, ran, skipped, executed),
        diagnostics=diagnostics,
        measurement={"tests": executed} if executed is not None else None,
        combined=combined,
    )


def _test_environment(python_prefix: list[str]) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("COVERAGE_") and name != "COVERAGE_CORE":
            del environment[name]
    environment["QG_PYTHON"] = json.dumps(python_prefix)
    return environment


def _combine_tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    data_dir: Path,
    combined_file: Path,
    config_file: Path,
    diagnostics: Diagnostics,
    deadline: float,
) -> CheckResult | None:
    reason = "coverage combination exceeded the remaining budget"
    if time.monotonic() >= deadline:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            reason,
            execution="budget",
            diagnostics=diagnostics,
        )
    try:
        combine_coverage(data_dir, combined_file, config_file)
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
    if time.monotonic() >= deadline:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            reason,
            execution="budget",
            diagnostics=diagnostics,
        )
    return None


def _run_python_tests(
    root: Path,
    check: CheckDef,
    *,
    prefix: str,
) -> CheckResult:
    assert check.python_tests is not None
    spec = check.python_tests
    start = time.monotonic()
    deadline = start + spec.budget_seconds
    temporary = tempfile.TemporaryDirectory(prefix="qg-coverage-")
    data_dir = Path(temporary.name) / "data"
    try:
        data_dir.mkdir()
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

    command = expand_run(spec.run, python_prefix)
    environment = _test_environment(python_prefix)
    run_result = run(
        command,
        cwd=root,
        env=environment,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    diagnostics = run_result.diagnostics()
    combined = run_result.combined_text
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

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline
    )
    if failure is not None:
        return failure
    if count_error is not None:
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
    assert ran is not None and skipped is not None
    executed = ran - skipped
    if executed == 0:
        return _tests_result(
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

    combined_file = Path(temporary.name) / "combined" / ".coverage"
    config_file = coverage_config_path(data_dir)
    failure = _combine_tests_evidence(
        check,
        spec,
        start,
        prefix,
        data_dir,
        combined_file,
        config_file,
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
        evidence_path=combined_file,
        coverage_config=config_file,
        temporary=temporary,
    )
    print(
        f"{prefix}: passed ({executed} tests, "
        f"{outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _file_present(path: Path | None) -> bool:
    return path is not None and path.is_file()


def _crap_missing_evidence(required: CheckResult) -> str | None:
    if not _file_present(required.evidence_path):
        return "combined coverage data"
    if not _file_present(required.coverage_config):
        return "gate coverage configuration"
    return None


def _crap_required(
    prior: dict[str, CheckResult],
    spec: Any,
    prefix: str,
) -> tuple[Path | None, Path | None, Diagnostics | None, str | None]:
    required = prior.get(spec.requires)
    if required is None or required.outcome != "pass":
        message = f"coverage unreliable: {spec.requires} did not pass"
    else:
        missing = _crap_missing_evidence(required)
        if missing is None:
            return required.evidence_path, required.coverage_config, None, None
        message = (
            f"coverage unreliable: {spec.requires} produced no {missing}"
        )
    print(f"{prefix}: {message}", file=sys.stderr)
    return None, None, Diagnostics(error=message), message


def _crap_measure(
    root: Path,
    selected: list[str],
    evidence_path: Path | None,
    config_path: Path | None,
    check: CheckDef,
    start: float,
    prefix: str,
) -> tuple[Any | None, CheckResult | None]:
    try:
        measurement = measure_crap(
            root,
            selected,
            evidence_path,
            config_path,
        )
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, _ratchet_result(
            check,
            start,
            "unsupported",
            diagnostics=Diagnostics(error=str(error)),
            reason=str(error),
        )
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, _ratchet_result(
            check,
            start,
            "error",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
            reason=str(error),
        )
    return measurement, None


def _run_python_crap(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    *,
    prefix: str,
    prior: dict[str, CheckResult],
) -> CheckResult:
    assert check.python_crap is not None
    spec = check.python_crap
    start = time.monotonic()
    deadline = start + CLONE_BUDGET_SECONDS

    selected, names = _select_files(config, check, files, classes)
    if not selected:
        class_text = _class_text(names)
        reason = (
            f"no files selected (classes: {class_text}); "
            "zero inputs is not a pass"
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(check, start, "fail", reason=reason)

    evidence_path, config_path, failure_diagnostics, message = _crap_required(
        prior, spec, prefix
    )
    if message is not None:
        return _ratchet_result(
            check,
            start,
            "unsupported",
            diagnostics=failure_diagnostics,
            reason=message,
        )

    measurement, failure = _crap_measure(
        root,
        selected,
        evidence_path,
        config_path,
        check,
        start,
        prefix,
    )
    if failure is not None:
        return failure
    assert measurement is not None
    if time.monotonic() >= deadline:
        reason = "analysis exceeded the remaining budget"
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(
            check, start, "fail", execution="budget", reason=reason
        )
    if measurement.failures:
        for failure in measurement.failures:
            print(f"{prefix}: {failure}", file=sys.stderr)
        diagnostics = _tail_diagnostics(
            measurement.failures, argv=None, exit_code=1
        )
        return _ratchet_result(
            check,
            start,
            "fail",
            diagnostics=diagnostics,
            reason=diagnostics.output_tail,
        )

    try:
        entries = load_baseline(
            check.baseline,
            check_id=check.id,
            metric_version=check.metric_version,
        )
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _ratchet_result(
            check,
            start,
            "error",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
            reason=str(error),
        )
    ratchet, failure = _evaluate_ratchet(
        measurement.findings,
        entries,
        check,
        prefix,
        Domain.of_files(selected),
    )
    if ratchet is None:
        return _ratchet_result(check, start, failure or "error", reason=failure)
    outcome = _ratchet_result(
        check,
        start,
        ratchet.outcome,
        ratchet=ratchet,
        measurement={"functions": len(measurement.findings)},
    )
    if ratchet.satisfied:
        noun = "function" if len(measurement.findings) == 1 else "functions"
        print(
            f"{prefix}: {len(measurement.findings)} {noun} within threshold",
            flush=True,
        )
    return outcome

def run_check(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    *,
    prefix: str,
    prior: dict[str, CheckResult] | None = None,
) -> CheckResult:
    if check.adapter == "command":
        return _run_command(root, config, check, files, classes, prefix)
    if check.adapter == "clones":
        return _run_clones(root, config, check, files, classes, prefix)
    if check.adapter == "python_tests":
        return _run_python_tests(root, check, prefix=prefix)
    if check.adapter == "python_crap":
        return _run_python_crap(
            root,
            config,
            check,
            files,
            classes,
            prefix=prefix,
            prior=prior or {},
        )
    raise GateError(f"unsupported adapter {check.adapter!r}")


def _skipped(check: CheckDef) -> CheckResult:
    if check.command is not None:
        budget = check.command.budget_seconds
    elif check.python_tests is not None:
        budget = check.python_tests.budget_seconds
    else:
        budget = CLONE_BUDGET_SECONDS
    return CheckResult(
        id=check.id,
        kind="check",
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        evidence=check.evidence,
        metric_version=check.metric_version,
        outcome="unsupported",
        execution="error",
        duration_seconds=0.0,
        budget_seconds=budget,
        threshold=check.threshold,
        baseline_path=check.baseline,
        reason="skipped because inventory failed",
    )


def _tail_text(messages: list[str]) -> tuple[str, int, bool]:
    encoded = "\n".join(messages).encode("utf-8")
    return (
        encoded[-4096:].decode("utf-8", "replace"),
        len(encoded),
        len(encoded) > 4096,
    )


def _tail_diagnostics(
    messages: list[str],
    *,
    argv: list[str] | None,
    exit_code: int,
) -> Diagnostics:
    tail, size, truncated = _tail_text(messages)
    return Diagnostics(
        argv=argv,
        exit_code=exit_code,
        output_bytes=size,
        output_tail=tail,
        output_truncated=truncated,
    )


def _builtin_result(
    identifier: str,
    *,
    ok: bool,
    duration_seconds: float,
    messages: list[str],
    execution: str,
    argv: list[str] | None,
) -> CheckResult:
    diagnostics = _tail_diagnostics(
        messages, argv=argv, exit_code=0 if ok else 1
    )
    return CheckResult(
        id=identifier,
        kind=identifier,
        tier=None,
        enforcement="enforced",
        adapter=identifier,
        evidence=(),
        metric_version=f"{identifier}/1",
        outcome="pass" if ok else "fail",
        execution=execution,
        duration_seconds=duration_seconds,
        budget_seconds=None,
        satisfied=ok,
        reason=None if ok else diagnostics.output_tail,
        diagnostics=diagnostics,
    )


def _run_inventory(
    root: Path, config: Config
) -> tuple[int, list[str], dict[str, str], list[str], str, float]:
    start = time.monotonic()
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        message = f"inventory: {error}"
        print(message, file=sys.stderr)
        return 1, [], {}, [message], "error", time.monotonic() - start
    if violations:
        messages = [f"inventory: {violation}" for violation in violations]
        for message in messages:
            print(message, file=sys.stderr)
        return 1, [], {}, messages, "completed", time.monotonic() - start
    print(f"inventory: {len(files)} files match {len(config.rules)} rules")
    return 0, files, classes, [], "completed", time.monotonic() - start


def _git_argv(root: Path, *args: str) -> list[str]:
    return [
        "git",
        "-c",
        f"safe.directory={root}",
        "-C",
        str(root),
        *args,
    ]


def _prune_option_error(
    root: Path, config: Config, prune_id: str, message: str
) -> tuple[int, dict[str, Any]]:
    print(message, file=sys.stderr)
    return 2, gate_result.error_document(
        root,
        config.path,
        message,
        prune={
            "requested": [prune_id],
            "performed": False,
            "reason": message,
        },
    )


def _run_policy_checks(
    root: Path,
    config: Config,
    files: list[str],
    classes: dict[str, str],
    inventory_code: int,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    prior: dict[str, CheckResult] = {}
    for check in config.checks.values():
        if inventory_code != 0:
            print(
                f"check: {check.id}: skipped because inventory failed",
                file=sys.stderr,
            )
            skipped = _skipped(check)
            results.append(skipped)
            prior[check.id] = skipped
            continue
        print(f"check: {check.id} ({check.adapter})", flush=True)
        outcome = run_check(
            root,
            config,
            check,
            files,
            classes,
            prefix=f"check: {check.id}",
            prior=prior,
        )
        results.append(outcome)
        prior[check.id] = outcome
    return results


def _write_pruned(check: CheckDef, result: CheckResult) -> tuple[bool, str | None]:
    assert check.baseline is not None
    existed = check.baseline.exists()
    try:
        assert result.ratchet is not None
        write_baseline(
            check.baseline,
            pruned_entries(result.ratchet),
            check_id=check.id,
            metric_version=check.metric_version,
        )
    except GateError as error:
        print(f"check: {check.id}: {error}", file=sys.stderr)
        return False, str(error)
    if check.baseline.exists():
        print(f"check: {check.id}: baseline updated at {check.baseline}")
    elif existed:
        print(f"check: {check.id}: baseline removed at {check.baseline}")
    return True, None


def _prune_refusal(prune_id: str) -> dict[str, Any]:
    reason = "the check did not pass; nothing written"
    print(
        f"check: {prune_id}: prune refused because the check did not "
        "pass; nothing written",
        file=sys.stderr,
    )
    return {"requested": [prune_id], "performed": False, "reason": reason}


def _perform_prune(
    config: Config, prune_id: str | None, results: list[CheckResult]
) -> dict[str, Any]:
    if prune_id is None:
        return {"requested": [], "performed": False, "reason": None}
    target = next(item for item in results if item.id == prune_id)
    check = config.checks[prune_id]
    if not target.is_satisfied() or target.ratchet is None:
        return _prune_refusal(prune_id)
    performed, reason = _write_pruned(check, target)
    return {
        "requested": [prune_id],
        "performed": performed,
        "reason": reason,
    }


def _builtin_failures(results: list[CheckResult]) -> list[str]:
    return [
        result.id
        for result in results
        if result.kind in ("inventory", "hygiene")
        and not result.is_satisfied()
    ]


def _enforced_failures(results: list[CheckResult]) -> list[str]:
    return [
        result.id
        for result in results
        if result.kind == "check"
        and result.enforcement == "enforced"
        and not result.is_satisfied()
    ]


def _failed_check_ids(results: list[CheckResult]) -> list[str]:
    return _builtin_failures(results) + _enforced_failures(results)


def _failure_names(
    results: list[CheckResult], obligations: list[dict[str, Any]]
) -> list[str]:
    failed = _failed_check_ids(results)
    failed.extend(
        f"obligation {item['class']} tier {item['tier']}"
        for item in obligations
        if item["status"] == "unsatisfied"
    )
    return failed


def _result_document(
    root: Path,
    config: Config,
    decision: str,
    results: list[CheckResult],
    obligations: list[dict[str, Any]],
    prune: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": 2,
        "gate_version": gate_result.gate_version(),
        "revision": gate_result.consumer_revision(root),
        "dirty": gate_result.consumer_dirty(root),
        "policy_sha256": gate_result.policy_sha256(config.path),
        "decision": decision,
        "checks": [result.to_json() for result in results],
        "obligations": obligations,
        "prune": prune,
    }


def _check_command(
    root: Path, config: Config, prune_id: str | None
) -> tuple[int, dict[str, Any]]:
    if prune_id is not None:
        if prune_id not in config.checks:
            message = (
                f"check: unknown check {prune_id!r}; known checks: "
                f"{', '.join(config.checks) or 'none'}"
            )
            return _prune_option_error(root, config, prune_id, message)
        if config.checks[prune_id].baseline is None:
            message = f"check: {prune_id}: no baseline to prune"
            return _prune_option_error(root, config, prune_id, message)

    print("check: inventory", flush=True)
    (
        inventory_code,
        files,
        classes,
        inventory_messages,
        inventory_execution,
        inventory_duration,
    ) = _run_inventory(root, config)
    inventory_result = _builtin_result(
        "inventory",
        ok=inventory_code == 0,
        duration_seconds=inventory_duration,
        messages=inventory_messages,
        execution=inventory_execution,
        argv=_git_argv(
            root, "ls-files", "-s", "-z", "-co", "--exclude-standard"
        ),
    )

    print("check: hygiene", flush=True)
    hygiene_start = time.monotonic()
    hygiene = hygiene_result(root, config)
    for message in hygiene.messages:
        print(message, file=sys.stderr)
    if hygiene.ok:
        print(hygiene.summary)
    hygiene_result_entry = _builtin_result(
        "hygiene",
        ok=hygiene.ok,
        duration_seconds=time.monotonic() - hygiene_start,
        messages=hygiene.messages,
        execution=hygiene.execution,
        argv=_git_argv(
            root, "ls-files", "-z", "-c", "-i", "--exclude-standard"
        ),
    )

    results = [inventory_result, hygiene_result_entry]
    results.extend(
        _run_policy_checks(root, config, files, classes, inventory_code)
    )
    obligations = gate_result.obligations(config, results)
    prune_document = _perform_prune(config, prune_id, results)
    prune_failed = prune_id is not None and not prune_document["performed"]

    decision = gate_result.decision(results, obligations)
    if decision == "rejected":
        print(
            f"check: failed "
            f"({', '.join(_failure_names(results, obligations))})",
            file=sys.stderr,
        )
    elif decision == "accepted_with_exceptions":
        print(
            f"check: passed with exceptions ({len(results)} checks)",
            flush=True,
        )
    else:
        print(f"check: passed ({len(results)} checks)", flush=True)

    exit_code = 0 if decision in ("accepted", "accepted_with_exceptions") else 1
    if prune_failed:
        exit_code = 1
    return exit_code, _result_document(
        root, config, decision, results, obligations, prune_document
    )


def command_check(
    root: Path,
    config: Config,
    *,
    json_output: bool = False,
    prune_id: str | None = None,
) -> int:
    if not json_output:
        return _check_command(root, config, prune_id)[0]
    with contextlib.redirect_stdout(sys.stderr):
        code, document = _check_command(root, config, prune_id)
    print(
        json.dumps(document, indent=2, allow_nan=False),
        file=sys.stdout,
    )
    return code
