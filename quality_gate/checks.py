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
from datetime import date
from functools import partial
from pathlib import Path
from typing import Any

from . import gate_result, reuse
from .adapters import AdapterContext, adapter_for
from .changes import apply_changes, changed_lines, location_coverage, resolve_revision
from .clones import measure_clones
from .coverage_tool import (
    combine_coverage,
    coverage_config_path,
)
from .files import git_argv, hygiene_result, validate_inventory
from .owners import measure_owners
from .policy import (
    CheckDef,
    Config,
    ConfigError,
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
    BaselineEntry,
    Domain,
    RatchetResult,
    evaluate,
    load_baseline,
    pruned_entries,
    write_baseline,
)
from .runner import (
    Diagnostics,
    RunResult,
    StepTimeout,
    WorkerError,
    analysis_step,
    check_deadline,
    check_time,
    mark_step,
    record_diagnostics,
    run,
)
from .tools import current_tools, tool_binary
from .tracing import TraceUnavailable
from .trust import checked_prune_path
from .verification import measure_verification


CLONE_BUDGET_SECONDS = 600
REGEX_RUNNER = Path(__file__).with_name("regexrun.py")


def _budget_detail(reason: str, start: float, budget: float) -> str:
    elapsed = time.monotonic() - start
    return f"{reason} (timeout; deadline: {budget:g} seconds; elapsed: {elapsed:.3f} seconds)"


@dataclass(frozen=True)
class TestResults:
    """One test adapter's normalized result, whatever the language."""

    selected: int
    passed: int
    failed: int
    failures: tuple[str, ...] = ()

    @property
    def skipped(self) -> int:
        return max(0, self.selected - self.passed - self.failed)


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
    test_results: TestResults | None = None
    tests_ran: int | None = None
    tests_skipped: int | None = None
    satisfied: bool | None = None
    reason: str | None = None
    diagnostics: Diagnostics = field(default_factory=Diagnostics)
    evidence_path: Path | None = None
    coverage_config: Path | None = None
    temporary: Any = field(default=None, repr=False, compare=False)
    configuration_error: bool = False
    change_scoped_failure: bool = False
    incomplete_locations: bool = False
    reused_from: str | None = None
    emacs_version: str | None = None
    definitions: list[dict[str, Any]] | None = None

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
            "location_coverage": self._location_coverage(),
        }
        document.update(self._json_test_fields())
        if self.reused_from is not None:
            document["reused_from"] = self.reused_from
        if self.measurement is not None:
            document["measurement"] = self.measurement
        return document

    def _json_test_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.test_results is not None:
            fields["test_results"] = {
                "selected": self.test_results.selected,
                "passed": self.test_results.passed,
                "failed": self.test_results.failed,
                "skipped": self.test_results.skipped,
                "failures": list(self.test_results.failures),
            }
        if self.emacs_version is not None:
            fields["emacs_version"] = self.emacs_version
        if self.definitions is not None:
            fields["definitions"] = self.definitions
        return fields

    def _location_coverage(self) -> str:
        coverage = location_coverage(self.adapter)
        if coverage == "complete" and _incomplete_locations(self):
            return "partial"
        return coverage


def _incomplete_locations(result: CheckResult) -> bool:
    return result.incomplete_locations or (
        result.ratchet is not None
        and any(item.locations is None for item in result.ratchet.findings)
    )


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


def _baseline_entries(check: CheckDef) -> list[BaselineEntry]:
    if check.effective_baseline is not None:
        return list(check.effective_baseline)
    assert check.baseline is not None
    descriptor = adapter_for(check.adapter)
    extras = descriptor.extras if descriptor is not None else ()
    return load_baseline(
        check.baseline,
        check_id=check.id,
        metric_version=check.metric_version,
        allowed_extras=extras,
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


def _check_result(
    check: CheckDef,
    start: float,
    outcome: str,
    *,
    execution: str = "completed",
    budget_seconds: int | None = None,
    **fields: Any,
) -> CheckResult:
    if execution != "budget":
        check_time()
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
            analysis_step(
                "ratchet evaluation",
                partial(
                    evaluate,
                    findings,
                    entries,
                    threshold=check.threshold,
                    enforcement=check.enforcement,
                    prefix=prefix,
                    adapter=check.adapter,
                    domain=domain,
                    direction=check.direction,
                ),
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
    deadline = time.monotonic() + max(0.0, budget_seconds)
    with tempfile.TemporaryDirectory(prefix="qg-regex-") as temporary:
        job = Path(temporary) / "job.json"
        analysis_step("output matching preparation", _write_pattern_job, job, patterns, text)
        mark_step("output matching")
        result = run(
            [sys.executable, "-I", str(REGEX_RUNNER), str(job)],
            budget_seconds=max(0.0, deadline - time.monotonic()),
        )
    if result.execution != "completed" or result.returncode != 0:
        return None, result
    try:
        return analysis_step("output matching analysis", json.loads, result.stdout_text), result
    except ValueError:
        return None, result


def _write_pattern_job(job: Path, patterns: dict[str, str], text: str) -> None:
    job.write_text(json.dumps({"text": text, "patterns": patterns}), encoding="utf-8")


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
    ran, skipped, count_error = analysis_step(
        "test count analysis", summarize_matches,
        spec, matches.get("tests", []), matches.get("skipped", []),
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


def _adapter_selection(
    context: AdapterContext,
) -> tuple[Any, float, list[str], list[str]]:
    check = context.check
    spec = check.spec
    start = time.monotonic()
    selected, names = analysis_step(
        "file selection", _select_files, context.config, check,
        context.files, context.classes,
    )
    return spec, start, selected, names


def _run_command(context: AdapterContext) -> CheckResult:
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
        reason=_ratchet_reason(ratchet, _ratchet_budget_reason(reason, execution, start)),
    )


def _ratchet_budget_reason(reason: str | None, execution: str, start: float) -> str | None:
    if execution == "budget" and reason is not None and "deadline:" not in reason:
        return _budget_detail(reason, start, CLONE_BUDGET_SECONDS)
    return reason


def _ratchet_error(
    check: CheckDef,
    start: float,
    prefix: str,
    error: Exception,
) -> CheckResult:
    message = str(error)
    print(f"{prefix}: {message}", file=sys.stderr)
    return _ratchet_result(
        check,
        start,
        "error",
        execution="error",
        diagnostics=Diagnostics(error=message),
        reason=message,
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


def _run_clones(context: AdapterContext) -> CheckResult:
    root, config = context.root, context.config
    check, files, prefix = context.check, context.files, context.prefix
    spec, start, selected, names = _adapter_selection(context)
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
        spec.min_tokens,
        config.max_bytes,
    )
    return _finish_clones(check, start, prefix, measurement, selected, files)


def _finish_clones(
    check: CheckDef,
    start: float,
    prefix: str,
    measurement: Any,
    selected: list[str],
    files: list[str],
) -> CheckResult:
    diagnostics = measurement.diagnostics
    record_diagnostics(diagnostics)
    if measurement.error is not None:
        return _clone_failure(check, start, prefix, measurement)
    try:
        entries = analysis_step("baseline loading", _baseline_entries, check)
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
    return _clone_ratchet(check, start, prefix, measurement, entries, selected, files)


def _clone_ratchet(
    check: CheckDef,
    start: float,
    prefix: str,
    measurement: Any,
    entries: list[Any],
    selected: list[str],
    files: list[str],
) -> CheckResult:
    diagnostics = measurement.diagnostics
    ratchet, failure = _evaluate_ratchet(
        measurement.findings,
        entries,
        check,
        prefix,
        analysis_step("clone domain analysis", _clone_domain, entries, selected, files),
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


def _clone_failure(check: CheckDef, start: float, prefix: str, measurement: Any) -> CheckResult:
    reason = measurement.error
    if measurement.execution == "budget":
        reason = _budget_detail(reason, start, CLONE_BUDGET_SECONDS)
    print(f"{prefix}: {reason}", file=sys.stderr)
    return _clone_result(
        check, start, outcome=_clone_outcome(measurement), execution=measurement.execution,
        diagnostics=measurement.diagnostics, reason=reason,
    )


def _print_output(prefix: str, combined: str) -> None:
    if combined.strip():
        print(combined.rstrip(), file=sys.stderr)


def _executed_tests(
    ran: int | None, skipped: int | None
) -> int | None:
    if ran is None or skipped is None:
        return None
    return ran - skipped


def _failed_test_results(
    ran: int | None, executed: int | None
) -> TestResults | None:
    if ran is None or executed is None:
        return None
    return TestResults(ran, 0, executed)


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
    if execution == "budget":
        reason = _budget_detail(reason, start, spec.budget_seconds)
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
    ran, skipped, error = analysis_step(
        "test count analysis", summarize_matches,
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
    test_results = _failed_test_results(ran, executed)
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
    data_dir: Path,
    combined_file: Path,
    config_file: Path,
    diagnostics: Diagnostics,
    deadline: float,
) -> CheckResult | None:
    reason = "coverage combination exceeded the remaining budget"
    try:
        analysis_step(
            "coverage combination", combine_coverage,
            data_dir, combined_file, config_file, deadline=deadline,
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
) -> tuple[tempfile.TemporaryDirectory, Path, list[str]] | CheckResult:
    session = reuse.current()
    temporary = (session.coverage_directory(check) if session is not None
                 else tempfile.TemporaryDirectory(prefix="qg-coverage-"))
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
) -> CheckResult | None:
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
) -> tuple[tuple[int, int, int] | None, CheckResult | None]:
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
    data_dir: Path,
    ran: int,
    skipped: int,
    executed: int,
    diagnostics: Diagnostics,
    deadline: float,
) -> CheckResult:
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
        test_results=TestResults(ran, executed, 0),
        tests_ran=ran,
        tests_skipped=skipped,
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


def _run_python_tests(context: AdapterContext) -> CheckResult:
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
        data_dir,
        ran,
        skipped,
        executed,
        diagnostics,
        deadline,
    )


def _run_elisp_tests(context: AdapterContext) -> CheckResult:
    from .elisp_tests import run_tests

    return run_tests(context)


def _run_elisp_lint(context: AdapterContext) -> CheckResult:
    from .elisp_lint import run_lint

    return run_lint(context)


def _run_elisp_crap(context: AdapterContext) -> CheckResult:
    from .elisp_crap import run_crap

    return run_crap(context)


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
        measurement = analysis_step(
            "CRAP analysis", measure_crap,
            root,
            selected,
            evidence_path,
            config_path,
            deadline=start + CLONE_BUDGET_SECONDS,
        )
    except StepTimeout:
        reason = _budget_detail(
            "CRAP analysis exceeded the remaining budget", start, CLONE_BUDGET_SECONDS
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return None, _ratchet_result(
            check, start, "fail", execution="budget", reason=reason
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
        return None, _ratchet_error(check, start, prefix, error)
    return measurement, None


def _run_python_crap(context: AdapterContext) -> CheckResult:
    root, check = context.root, context.check
    prefix, prior = context.prefix, context.prior
    spec, start, selected, names = _adapter_selection(context)
    if not selected:
        class_text = _class_text(names)
        reason = (
            f"no files selected (classes: {class_text}); "
            "zero inputs is not a pass"
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(check, start, "fail", reason=reason)

    evidence_path, config_path, failure_diagnostics, message = analysis_step(
        "coverage evidence validation", _crap_required, prior, spec, prefix
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
        entries = analysis_step("baseline loading", _baseline_entries, check)
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

def _produces_tests(adapter: str) -> bool:
    descriptor = adapter_for(adapter)
    return descriptor is not None and descriptor.produces_tests


def _verification_test_checks(
    check: CheckDef, prior: dict[str, CheckResult]
) -> list[str]:
    spec = check.spec
    if spec.requires is not None:
        return [spec.requires]
    return [
        identifier
        for identifier, result in prior.items()
        if _produces_tests(result.adapter)
    ]


def _recorded_test_counts(
    result: CheckResult,
) -> tuple[int, int] | None:
    if result.test_results is not None:
        return result.test_results.selected, result.test_results.skipped
    if result.tests_ran is not None and result.tests_skipped is not None:
        return result.tests_ran, result.tests_skipped
    return None


def _missing_test_count(
    identifier: str, result: CheckResult
) -> str | None:
    if _recorded_test_counts(result) is None:
        return (
            f"test counts unreliable: {identifier} recorded no "
            "ran/skipped counts"
        )
    return None


def _count_problem(
    identifier: str, result: CheckResult | None
) -> str | None:
    if result is None:
        return f"test counts unreliable: {identifier} did not run"
    if result.outcome != "pass":
        return f"test counts unreliable: {identifier} did not pass"
    return _missing_test_count(identifier, result)


def _verification_counts(
    check: CheckDef, prior: dict[str, CheckResult]
) -> tuple[list[tuple[str, int, int]] | None, str | None]:
    identifiers = _verification_test_checks(check, prior)
    if not identifiers:
        return None, "no python_tests check to measure"
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


def _verification_selection(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    start: float,
    prefix: str,
) -> tuple[list[str] | None, CheckResult | None]:
    selected, names = analysis_step(
        "file selection", _select_files, config, check, files, classes
    )
    python_files = analysis_step("Python file selection", _verification_files, selected)
    if python_files:
        return python_files, None
    class_text = _class_text(names)
    reason = (
        f"no Python files selected (classes: {class_text}); "
        "zero inputs is not a pass"
    )
    print(f"{prefix}: {reason}", file=sys.stderr)
    return None, _ratchet_result(check, start, "fail", reason=reason)


def _verification_findings(
    root: Path,
    check: CheckDef,
    files: list[str],
    prior: dict[str, CheckResult],
    start: float,
    prefix: str,
) -> list[Any] | CheckResult:
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
            deadline=start + CLONE_BUDGET_SECONDS,
        )
    except StepTimeout:
        reason = _budget_detail(
            "verification analysis exceeded the remaining budget", start, CLONE_BUDGET_SECONDS
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
    prior: dict[str, CheckResult],
    start: float,
    prefix: str,
) -> list[Any] | CheckResult:
    python_files, failure = _verification_selection(
        root, config, check, files, classes, start, prefix
    )
    if failure is not None:
        return failure
    assert python_files is not None
    return _verification_findings(
        root, check, python_files, prior, start, prefix
    )


def _verification_entries(
    check: CheckDef, start: float, prefix: str
) -> tuple[list[Any] | None, CheckResult | None]:
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
) -> CheckResult:
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


def _run_verification(context: AdapterContext) -> CheckResult:
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


def _owners_report(findings: list[Any]) -> None:
    for finding in findings:
        details = finding.measurement
        assert details is not None
        path = finding.location.rsplit(":", 1)[0]
        owners = ", ".join(details["owners"])
        for line in details["lines"]:
            print(
                f"owners: {details['rule']}: {path}:{line}: "
                f"{details['pattern']} outside its owners ({owners})",
                file=sys.stderr,
            )


def _owners_error(check: CheckDef, start: float, prefix: str, error: GateError) -> CheckResult:
    result = _ratchet_error(check, start, prefix, error)
    result.configuration_error = isinstance(error, ConfigError)
    return result


def _run_owners(context: AdapterContext) -> CheckResult:
    root, check = context.root, context.check
    files, prefix = context.files, context.prefix
    start = time.monotonic()
    try:
        findings = analysis_step("owners analysis", measure_owners, root, files, check.spec)
        entries = analysis_step("baseline loading", _baseline_entries, check)
    except GateError as error:
        return _owners_error(check, start, prefix, error)
    _owners_report(findings)
    ratchet, failure = _evaluate_ratchet(findings, entries, check, prefix, Domain.all("the full inventory"))
    if ratchet is None:
        return _ratchet_result(check, start, failure or "error", reason=failure)
    if ratchet.satisfied:
        print(f"{prefix}: {len(findings)} subjects within baseline", flush=True)
    return _ratchet_result(check, start, ratchet.outcome, ratchet=ratchet)


def _check_descriptor(check: CheckDef) -> Any:
    descriptor = adapter_for(check.adapter)
    if descriptor is None:
        raise GateError(f"unsupported adapter {check.adapter!r}")
    return descriptor


def _adapter_runner(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prefix: str,
    prior: dict[str, CheckResult],
) -> CheckResult:
    return _check_descriptor(check).run(
        root, config, check, files, classes, prefix=prefix, prior=prior
    )


def _reused_result(
    check: CheckDef, start: float, prefix: str, reused: reuse.Reused
) -> CheckResult:
    record = reused.record
    result = _check_result(
        check,
        start,
        "pass",
        budget_seconds=_check_budget(check),
        measurement=record.get("measurement"),
        tests_ran=record.get("tests_ran"),
        tests_skipped=record.get("tests_skipped"),
        emacs_version=record.get("emacs_version"),
    )
    reuse.restore_coverage(record, result)
    if result.tests_ran is not None and result.tests_skipped is not None:
        result.test_results = TestResults(result.tests_ran, result.tests_ran - result.tests_skipped, 0)
    if "elisp_result" in record:
        from .elisp_tests import apply_document

        apply_document(result, record["elisp_result"])
        reuse.restore_elisp(record, result)
    result.duration_seconds = 0.0
    result.reused_from = str(reused.tree)
    version = f" (Emacs {result.emacs_version})" if result.emacs_version is not None else ""
    print(f"{prefix}: reused record at {reused.tree}{version}", flush=True)
    return result


def _reuse_unavailable(
    check: CheckDef, start: float, prefix: str, error: TraceUnavailable
) -> CheckResult:
    message = str(error)
    print(f"{prefix}: {message}", file=sys.stderr)
    return _check_result(
        check,
        start,
        "unsupported",
        execution="error",
        budget_seconds=_check_budget(check),
        diagnostics=Diagnostics(error=message),
        reason=message,
    )


def _reuse_selection(
    config: Config, check: CheckDef, files: list[str], classes: dict[str, str]
) -> tuple[list[str], list[str]]:
    if check.adapter == "python_tests":
        return [], []
    if check.adapter == "command" and "{files}" not in check.spec.run:
        return [], []
    return _select_files(config, check, files, classes)


def _entry_expired(entry: BaselineEntry, today: date) -> bool:
    return entry.expires is not None and entry.expires < today


def _reuse_expired_entries(check: CheckDef) -> list[str] | None:
    if check.baseline is None:
        return []
    try:
        entries = _baseline_entries(check)
    except GateError:
        return None
    today = date.today()
    return [entry.subject for entry in entries if _entry_expired(entry, today)]


def _elisp_reuse_files(
    root: Path, config: Config, check: CheckDef, selected: list[str],
    files: list[str], classes: dict[str, str],
) -> dict[str, Any] | None:
    if check.adapter == "elisp_tests":
        inputs = selected
    elif check.adapter == "elisp_crap":
        required = config.checks[check.spec.requires]
        inputs, _names = _select_files(config, required, files, classes)
    else:
        return None
    from .elisp_crap import _file_key

    return {name: _file_key(root, name) for name in inputs}


def _reuse_context(
    root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], prior: dict[str, CheckResult],
) -> dict[str, Any]:
    selected, names = _reuse_selection(config, check, files, classes)
    descriptor = _check_descriptor(check)
    depends_on_tests = descriptor.requires_tests or getattr(check.spec, "requires", None) is not None
    dependencies = prior if depends_on_tests else {}
    _lock, tools = current_tools()
    return {
        "root": str(root),
        "tools": {name: reuse._spec_text(tool) for name, tool in sorted(tools.items())},
        "check": reuse._spec_text(check),
        "expired_entries": _reuse_expired_entries(check),
        "selection": selected,
        "classes": names,
        "elisp_files": _elisp_reuse_files(root, config, check, selected, files, classes),
        "prior": {name: [result.outcome, result.tests_ran, result.tests_skipped,
                          result.measurement, reuse.evidence_hash(result.evidence_path)]
                  for name, result in dependencies.items()},
    }


def _reuse_identity(check: CheckDef, context: Any, root: Path, coverage_dir: Path | None) -> Any:
    try:
        return reuse.check_identity(check, context, root, coverage_dir)
    except UnsupportedError:
        return None


def _lint_reuse_missing(check: CheckDef, record: dict[str, Any]) -> bool:
    return check.adapter in ("elisp_compile", "elisp_checkdoc") and "emacs_version" not in record


def _usable_reuse(check: CheckDef, reused: Any) -> Any:
    if reused is None:
        return None
    if check.adapter == "elisp_tests" and "elisp_result" not in reused.record:
        return None
    if _lint_reuse_missing(check, reused.record):
        return None
    return reused


def _reuse_lookup(session: Any, check: CheckDef, identity: Any, coverage_dir: Path | None) -> Any:
    if identity is None or check.id == session.prune_id:
        return None
    if coverage_dir is not None and os.path.lexists(coverage_dir):
        return None
    return _usable_reuse(check, session.lookup(identity))


def _run_recorded_check(
    session: Any, identity: Any, root: Path, config: Config, check: CheckDef,
    files: list[str], classes: dict[str, str], prefix: str,
    prior: dict[str, CheckResult], start: float, tracer: tuple[str, ...],
) -> CheckResult:
    with session.collect(check, tracer) as recorder:
        result = _run_check_with_deadline(root, config, check, files, classes, prefix, prior, start)
    if _recordable(identity, result, recorder):
        session.record(identity, recorder, result)
    return result


def _recordable(identity: Any, result: CheckResult, recorder: Any) -> bool:
    return (identity is not None and result.outcome == "pass"
            and result.execution == "completed" and recorder.reliable)


def _elisp_reuse_collision(
    root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], prefix: str, prior: dict[str, CheckResult], start: float,
) -> CheckResult | None:
    from .elisp_tests import _suite_collision

    selected, _names = _select_files(config, check, files, classes)
    context = AdapterContext(root, config, check, files, classes, prefix, prior)
    return _suite_collision(context, selected, start)


def _elisp_reuse_selection(
    root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], prefix: str, prior: dict[str, CheckResult], start: float,
) -> CheckResult | None:
    if check.adapter == "elisp_tests":
        return _elisp_reuse_collision(root, config, check, files, classes, prefix, prior, start)
    from .elisp_crap import selection_failure

    context = AdapterContext(root, config, check, files, classes, prefix, prior)
    return selection_failure(context, start)


def _reuse_stages(
    session: Any, root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], prefix: str, prior: dict[str, CheckResult], start: float,
    budget: float,
) -> CheckResult:
    deadline = start + budget
    if check.adapter in ("elisp_tests", "elisp_crap"):
        selection = analysis_step("Elisp selection", _elisp_reuse_selection, root, config, check,
                                  files, classes, prefix, prior, start, deadline=deadline)
        if selection is not None:
            return selection
    context = analysis_step("reuse context", _reuse_context, root, config, check, files, classes, prior,
                            deadline=deadline)
    coverage_dir = session.coverage_path(check) if check.adapter == "python_tests" else None
    identity = analysis_step("reuse identity", _reuse_identity, check, context, root, coverage_dir,
                             deadline=deadline)
    tracer = analysis_step("reuse tracer verification", session._require_tracer, deadline=deadline)
    reused = analysis_step("reuse lookup", _reuse_lookup, session, check, identity, coverage_dir,
                           deadline=deadline)
    if reused is not None:
        return _reused_result(check, start, prefix, reused)
    return _run_recorded_check(session, identity, root, config, check, files, classes, prefix,
                               prior, start, tracer)


def _reuse_check(
    root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], prefix: str, prior: dict[str, CheckResult],
) -> CheckResult:
    session = reuse.current()
    assert session is not None
    start = time.monotonic()
    budget = _check_budget(check)
    try:
        return _reuse_stages(session, root, config, check, files, classes, prefix, prior, start, budget)
    except TraceUnavailable as error:
        return _reuse_unavailable(check, start, prefix, error)
    except (StepTimeout, WorkerError) as error:
        return _deadline_failure(check, prefix, start, budget, None, error)


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
    _check_descriptor(check)
    if reuse.current() is None:
        return _run_check_with_deadline(
            root, config, check, files, classes, prefix, prior or {}
        )
    return _reuse_check(
        root, config, check, files, classes, prefix, prior or {}
    )


def _check_budget(check: CheckDef) -> float:
    return _check_descriptor(check).budget(check.spec)


def _run_check_with_deadline(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prefix: str,
    prior: dict[str, CheckResult],
    started: float | None = None,
) -> CheckResult:
    budget = _check_budget(check)
    start = time.monotonic() if started is None else started
    with check_deadline(start, budget) as scope:
        try:
            result = _adapter_runner(
                root, config, check, files, classes, prefix, prior
            )
            check_time()
        except (StepTimeout, WorkerError) as error:
            failure = error
        else:
            failure = None
    if failure is None:
        return result
    return _deadline_failure(check, prefix, start, budget, scope.diagnostics, failure)


def _deadline_failure(
    check: CheckDef,
    prefix: str,
    start: float,
    budget: float,
    diagnostics: Diagnostics | None,
    failure: StepTimeout | WorkerError,
) -> CheckResult:
    if isinstance(failure, StepTimeout):
        reason = _budget_detail(
            f"{failure} exceeded the remaining budget", start, budget
        )
        execution = "budget"
        outcome = "fail"
    else:
        reason = str(failure)
        execution = "error"
        outcome = "error"
    print(f"{prefix}: {reason}", file=sys.stderr)
    return _check_result(
        check, start, outcome, execution=execution, budget_seconds=budget,
        diagnostics=diagnostics or Diagnostics(error=reason), reason=reason,
    )


def _skipped(check: CheckDef) -> CheckResult:
    budget = _check_budget(check)
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


def _record_prune(
    trust: Any, destination: Path, written: bytes | None
) -> None:
    if trust is not None:
        trust.record_prune_write(destination, written)


def _write_pruned(
    check: CheckDef,
    result: CheckResult,
    destination: Path,
    trust: Any = None,
) -> tuple[bool, str | None]:
    existed = destination.exists()
    try:
        assert result.ratchet is not None
        written = write_baseline(
            destination,
            pruned_entries(result.ratchet),
            check_id=check.id,
            metric_version=check.metric_version,
        )
    except GateError as error:
        print(f"check: {check.id}: {error}", file=sys.stderr)
        return False, str(error)
    _record_prune(trust, destination, written)
    if destination.exists():
        print(f"check: {check.id}: baseline updated at {destination}")
    elif existed:
        print(f"check: {check.id}: baseline removed at {destination}")
    return True, None


def _prune_refusal(prune_id: str) -> dict[str, Any]:
    reason = "the check did not pass; nothing written"
    print(
        f"check: {prune_id}: prune refused because the check did not "
        "pass; nothing written",
        file=sys.stderr,
    )
    return {"requested": [prune_id], "performed": False, "reason": reason}


def _checked_prune_destination(
    config: Config,
    prune_id: str,
    destination: Path,
    trust: Any = None,
) -> tuple[Path | None, str | None]:
    if trust is not None:
        refusal = trust.before_prune()
        if refusal is not None:
            return None, refusal
    if prune_id not in config.prune_paths:
        return destination, None
    try:
        return checked_prune_path(config.root, destination), None
    except UsageError as error:
        print(f"check: {prune_id}: {error}", file=sys.stderr)
        return None, str(error)


def _prune_check_result(
    results: list[CheckResult], prune_id: str
) -> CheckResult:
    return next(item for item in results if item.id == prune_id)


def _prune_allowed(results: list[CheckResult], target: CheckResult) -> bool:
    return (
        not any(result.configuration_error for result in results)
        and target.is_satisfied()
        and target.ratchet is not None
    )


def _perform_prune(
    config: Config,
    prune_id: str | None,
    results: list[CheckResult],
    trust: Any = None,
) -> dict[str, Any]:
    if prune_id is None:
        return {"requested": [], "performed": False, "reason": None}
    target = _prune_check_result(results, prune_id)
    check = config.checks[prune_id]
    if not _prune_allowed(results, target):
        return _prune_refusal(prune_id)
    assert check.baseline is not None
    destination = config.prune_paths.get(prune_id, check.baseline)
    destination, refusal = _checked_prune_destination(
        config, prune_id, destination, trust
    )
    if destination is None:
        return {
            "requested": [prune_id],
            "performed": False,
            "reason": refusal,
        }
    performed, reason = _write_pruned(
        check, target, destination, trust
    )
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
        and (result.enforcement == "enforced" or result.change_scoped_failure)
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
    trust: Any = None,
) -> dict[str, Any]:
    return {
        "schema": 2,
        "gate_version": gate_result.gate_version(),
        "revision": gate_result.consumer_revision(root),
        "dirty": gate_result.consumer_dirty(root),
        "policy_sha256": (
            trust.policy_sha256 if trust is not None
            else gate_result.policy_sha256(config.path)
        ),
        "decision": decision,
        "checks": [result.to_json() for result in results],
        "obligations": obligations,
        "prune": prune,
    }


def _prune_request_problem(config: Config, prune_id: str | None) -> str | None:
    if prune_id is None:
        return None
    if prune_id not in config.checks:
        return (
            f"check: unknown check {prune_id!r}; known checks: "
            f"{', '.join(config.checks) or 'none'}"
        )
    if config.checks[prune_id].baseline is None:
        return f"check: {prune_id}: no baseline to prune"
    return None


def _inventory_check(root: Path, config: Config) -> tuple[CheckResult, list[str], dict[str, str], int]:
    print("check: inventory", flush=True)
    (
        inventory_code,
        files,
        classes,
        inventory_messages,
        inventory_execution,
        inventory_duration,
    ) = _run_inventory(root, config)
    result = _builtin_result(
        "inventory",
        ok=inventory_code == 0,
        duration_seconds=inventory_duration,
        messages=inventory_messages,
        execution=inventory_execution,
        argv=git_argv(
            root, "ls-files", "-s", "-z", "-co", "--exclude-standard"
        ),
    )

    return result, files, classes, inventory_code


def _hygiene_check(root: Path, config: Config) -> CheckResult:
    print("check: hygiene", flush=True)
    hygiene_start = time.monotonic()
    hygiene = hygiene_result(root, config)
    for message in hygiene.messages:
        print(message, file=sys.stderr)
    if hygiene.ok:
        print(hygiene.summary)
    return _builtin_result(
        "hygiene",
        ok=hygiene.ok,
        duration_seconds=time.monotonic() - hygiene_start,
        messages=hygiene.messages,
        execution=hygiene.execution,
        argv=git_argv(
            root, "ls-files", "-z", "-c", "-i", "--exclude-standard"
        ),
    )

def _print_decision(
    decision: str, configuration_error: str | None,
    results: list[CheckResult], obligations: list[dict[str, Any]],
) -> None:
    if decision == "error":
        print(f"check: error: {configuration_error}", file=sys.stderr)
    elif decision == "rejected":
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



def _decision_exit_code(decision: str, prune_id: str | None, prune: dict[str, Any]) -> int:
    if decision == "error":
        return 2
    if decision not in ("accepted", "accepted_with_exceptions"):
        return 1
    return 1 if prune_id is not None and not prune["performed"] else 0


def _finalize_check(
    root: Path, config: Config, results: list[CheckResult],
    prune_id: str | None, trust: Any,
) -> tuple[int, dict[str, Any]]:
    obligations = gate_result.obligations(config, results)
    prune_document = _perform_prune(config, prune_id, results, trust)
    configuration_error = next((result.reason for result in results if result.configuration_error), None)
    decision = "error" if configuration_error is not None else gate_result.decision(results, obligations)
    _print_decision(decision, configuration_error, results, obligations)
    exit_code = _decision_exit_code(decision, prune_id, prune_document)
    document = _result_document(
        root, config, decision, results, obligations, prune_document, trust
    )
    if configuration_error is not None:
        document["error"] = configuration_error
    return exit_code, document


def _check_command(
    root: Path,
    config: Config,
    prune_id: str | None,
    trust: Any = None,
    changed_from: str | None = None,
) -> tuple[int, dict[str, Any]]:
    revision = resolve_revision(root, changed_from) if changed_from is not None else None
    problem = _prune_request_problem(config, prune_id)
    if problem is not None:
        assert prune_id is not None
        return _prune_option_error(root, config, prune_id, problem)
    inventory, files, classes, code = _inventory_check(root, config)
    results = [inventory, _hygiene_check(root, config)]
    results.extend(_run_policy_checks(root, config, files, classes, code))
    if revision is not None:
        apply_changes(results, changed_lines(root, revision, files))
    exit_code, document = _finalize_check(root, config, results, prune_id, trust)
    if revision is not None:
        document["changed_from"] = revision
    return exit_code, document


def _run_check_document(
    root: Path,
    config: Config,
    prune_id: str | None,
    json_output: bool,
    trust: Any = None,
    changed_from: str | None = None,
) -> tuple[int, dict[str, Any]]:
    if not json_output:
        return _check_command(root, config, prune_id, trust, changed_from)
    with contextlib.redirect_stdout(sys.stderr):
        return _check_command(root, config, prune_id, trust, changed_from)


def command_check(
    root: Path,
    config: Config,
    *,
    json_output: bool = False,
    prune_id: str | None = None,
    trust: Any = None,
    changed_from: str | None = None,
    reuse_store: str | None = None,
    record_fd: int | None = None,
) -> int:
    store = Path(reuse_store).expanduser() if reuse_store else None
    with reuse.active(store, root, record_fd, prune_id):
        if trust is None:
            code, document = _run_check_document(
                root, config, prune_id, json_output, changed_from=changed_from
            )
        else:
            try:
                with trust.activate():
                    code, document = _run_check_document(
                        root, config, prune_id, json_output, trust, changed_from
                    )
                code, document = trust.finish(code, document)
            finally:
                trust.close()
    if json_output:
        print(
            json.dumps(document, indent=2, allow_nan=False),
            file=sys.stdout,
        )
    return code
