"""Check adapters, the check runner and the combined check command."""
from __future__ import annotations

import contextlib
import json
import re
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from . import gate_result
from .adapters import AdapterContext, adapter_for
from .changes import apply_changes, changed_lines, location_coverage, resolve_revision
from .clones import measure_clones
from .files import git_argv, hygiene_result, validate_inventory
from .json_input import load_json
from .owners import measure_owners
from .policy import (
    CheckDef,
    Config,
    ConfigError,
    GateError,
    UnsupportedError,
    UsageError,
)
from .python_tests import summarize_matches
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
from .trust import checked_prune_path


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
    adapter_data: Any = None
    temporary: Any = field(default=None, repr=False, compare=False)
    configuration_error: bool = False
    change_scoped_failure: bool = False
    incomplete_locations: bool = False
    tool: dict[str, str] | None = None
    report_fields: dict[str, Any] = field(default_factory=dict)

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
        document.update(self.report_fields)
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
        if self.tool is not None:
            fields["tool"] = self.tool
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
        adapter=check.adapter,
        direction=check.direction,
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
        return analysis_step("output matching analysis", load_json, result.stdout_text), result
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


def _command_test_fields(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    matches: dict[str, Any],
    diagnostics: Diagnostics,
    combined: str,
) -> tuple[dict[str, Any], CheckResult | None]:
    if spec.tests_pattern_re is None:
        return {}, None
    ran, skipped, count_error = analysis_step(
        "test count analysis", summarize_matches,
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


def _test_check_dependencies(
    check: CheckDef, prior: Mapping[str, CheckResult | CheckDef]
) -> list[str]:
    spec = check.spec
    if spec.requires is not None:
        return [spec.requires]
    return [
        identifier
        for identifier, result in prior.items()
        if "tests" in result.evidence
    ]


def _owners_message(path: str, line: int, details: dict[str, Any]) -> str:
    if details.get("kind") == "unanalysable":
        return f"owners: {path}:{line}: unanalysable {details['word']!r}: {details['reason']}"
    owners = ", ".join(details["owners"])
    return f"owners: {details['rule']}: {path}:{line}: {details['pattern']} outside its owners ({owners})"


def _owners_report(findings: list[Any]) -> None:
    for finding in findings:
        details = finding.measurement
        assert details is not None
        path = finding.location.rsplit(":", 1)[0]
        for line in details["lines"]:
            print(_owners_message(path, line, details), file=sys.stderr)


def _owners_baseline(findings: list[Any], entries: list[Any]) -> list[Any]:
    uncertain = {finding.subject for finding in findings if finding.kind == "unanalysable"}
    return [entry for entry in entries if entry.subject not in uncertain]


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
    ratchet, failure = _evaluate_ratchet(
        findings, _owners_baseline(findings, entries), check, prefix, Domain.all("the full inventory")
    )
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
    context = AdapterContext(root, config, check, files, classes, prefix, prior)
    return _check_descriptor(check).run(context)


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
    return _run_check_with_deadline(
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
) -> CheckResult:
    budget = _check_budget(check)
    start = time.monotonic()
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
    root: Path, config: Config, requested: list[str], message: str
) -> tuple[int, dict[str, Any]]:
    print(message, file=sys.stderr)
    return 2, gate_result.error_document(
        root,
        config.path,
        message,
        prune={
            "requested": requested,
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


def _prune_refusal(prune_id: str, requested: list[str]) -> dict[str, Any]:
    reason = "the check did not pass; nothing written"
    print(
        f"check: {prune_id}: prune refused because the check did not "
        "pass; nothing written",
        file=sys.stderr,
    )
    return {"requested": requested, "performed": False, "reason": reason}


def _checked_prune_destination(
    config: Config,
    prune_id: str,
    destination: Path,
) -> tuple[Path | None, str | None]:
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
    requested: list[str],
    results: list[CheckResult],
    trust: Any = None,
) -> dict[str, Any]:
    if not requested:
        return {"requested": [], "performed": False, "reason": None}
    ids = _expand_prune_ids(config, requested)
    refusal = _prune_targets_refusal(results, ids, requested)
    if refusal is not None:
        return refusal
    return _guarded_prune(config, ids, requested, results, trust)


def _guarded_prune(
    config: Config, ids: list[str], requested: list[str],
    results: list[CheckResult], trust: Any,
) -> dict[str, Any]:
    if trust is not None:
        reason = trust.before_prune()
        if reason is not None:
            return {"requested": requested, "performed": False, "reason": reason}
    destinations, reason = _prune_destinations(config, ids)
    if reason is not None:
        return {"requested": requested, "performed": False, "reason": reason}
    return _write_prune_set(config, results, requested, destinations, trust)


def _write_prune_set(
    config: Config, results: list[CheckResult], requested: list[str],
    destinations: list[tuple[str, Path]], trust: Any,
) -> dict[str, Any]:
    for identifier, destination in destinations:
        target = _prune_check_result(results, identifier)
        performed, reason = _write_pruned(config.checks[identifier], target, destination, trust)
        if not performed:
            return {"requested": requested, "performed": False, "reason": reason}
    return {"requested": requested, "performed": True, "reason": None}


def _prune_targets_refusal(
    results: list[CheckResult], ids: list[str], requested: list[str]
) -> dict[str, Any] | None:
    if "all" in requested:
        failure = _first_unsatisfied(results)
        if failure is not None:
            return _prune_refusal(failure.id, requested)
    for identifier in ids:
        if not _prune_allowed(results, _prune_check_result(results, identifier)):
            return _prune_refusal(identifier, requested)
    return None


def _first_unsatisfied(results: list[CheckResult]) -> CheckResult | None:
    return next((result for result in results if not result.is_satisfied()), None)


def _prune_destinations(
    config: Config, ids: list[str]
) -> tuple[list[tuple[str, Path]], str | None]:
    destinations = []
    for identifier in ids:
        check = config.checks[identifier]
        assert check.baseline is not None
        path = config.prune_paths.get(identifier, check.baseline)
        destination, reason = _checked_prune_destination(config, identifier, path)
        if destination is None:
            return [], reason
        destinations.append((identifier, destination))
    return destinations, None


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


def _prune_id_problem(config: Config, prune_id: str) -> str | None:
    if prune_id == "all":
        return None
    if prune_id not in config.checks:
        return (
            f"check: unknown check {prune_id!r}; known checks: "
            f"{', '.join(config.checks) or 'none'}"
        )
    if config.checks[prune_id].baseline is None:
        return f"check: {prune_id}: no baseline to prune"
    return None


def _prune_request_problem(config: Config, requested: list[str]) -> str | None:
    return next((problem for identifier in requested
                 if (problem := _prune_id_problem(config, identifier)) is not None), None)


def _expand_prune_ids(config: Config, requested: list[str]) -> list[str]:
    return list(dict.fromkeys(
        choice for identifier in requested for choice in _prune_choices(config, identifier)
    ))


def _prune_choices(config: Config, identifier: str) -> list[str]:
    if identifier == "all":
        return [check.id for check in config.checks.values() if check.baseline is not None]
    return [identifier]


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



def _decision_exit_code(decision: str, prune_ids: list[str], prune: dict[str, Any]) -> int:
    if decision == "error":
        return 2
    if decision not in ("accepted", "accepted_with_exceptions"):
        return 1
    return 1 if prune_ids and not prune["performed"] else 0


def _finalize_check(
    root: Path, config: Config, results: list[CheckResult],
    prune_ids: list[str], trust: Any,
) -> tuple[int, dict[str, Any]]:
    obligations = gate_result.obligations(config, results)
    prune_document = _perform_prune(config, prune_ids, results, trust)
    configuration_error = next((result.reason for result in results if result.configuration_error), None)
    decision = "error" if configuration_error is not None else gate_result.decision(results, obligations)
    _print_decision(decision, configuration_error, results, obligations)
    exit_code = _decision_exit_code(decision, prune_ids, prune_document)
    document = _result_document(
        root, config, decision, results, obligations, prune_document, trust
    )
    if configuration_error is not None:
        document["error"] = configuration_error
    return exit_code, document


def _check_command(
    root: Path,
    config: Config,
    prune_ids: list[str],
    trust: Any = None,
    changed_from: str | None = None,
) -> tuple[int, dict[str, Any]]:
    revision = resolve_revision(root, changed_from) if changed_from is not None else None
    problem = _prune_request_problem(config, prune_ids)
    if problem is not None:
        return _prune_option_error(root, config, prune_ids, problem)
    inventory, files, classes, code = _inventory_check(root, config)
    results = [inventory, _hygiene_check(root, config)]
    results.extend(_run_policy_checks(root, config, files, classes, code))
    if revision is not None:
        apply_changes(results, changed_lines(root, revision, files))
    exit_code, document = _finalize_check(root, config, results, prune_ids, trust)
    if revision is not None:
        document["changed_from"] = revision
    return exit_code, document


def _run_check_document(
    root: Path,
    config: Config,
    prune_ids: list[str],
    json_output: bool,
    trust: Any = None,
    changed_from: str | None = None,
) -> tuple[int, dict[str, Any]]:
    if not json_output:
        return _check_command(root, config, prune_ids, trust, changed_from)
    with contextlib.redirect_stdout(sys.stderr):
        return _check_command(root, config, prune_ids, trust, changed_from)


def command_check(
    root: Path,
    config: Config,
    *,
    json_output: bool = False,
    prune_ids: list[str] | None = None,
    trust: Any = None,
    changed_from: str | None = None,
) -> int:
    requested = prune_ids or []
    if trust is None:
        code, document = _run_check_document(
            root, config, requested, json_output, changed_from=changed_from
        )
    else:
        try:
            with trust.activate():
                code, document = _run_check_document(
                    root, config, requested, json_output, trust, changed_from
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
