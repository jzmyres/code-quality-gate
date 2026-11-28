"""Shared check machinery, the check runner and the combined check command.

DECISION_MESSAGES supplies the accepted decisions for both reporting
and exit-status selection.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

from . import gate_result
from .adapters import (
    AdapterContext,
    AdapterDescriptor,
    DependencyEvidence,
    GraphCache,
    adapter_for,
    affected_graph,
    extract_contract_graph,
    is_files_argument,
    module_contract_findings,
    module_ownership,
)
from .files import (
    BUILTIN_RESULT_KINDS,
    DiffBase,
    DiffBaseOverride,
    InventoryClasses,
    _git,
    _split_nul,
    affected_diff,
    changed_paths,
    hygiene_result,
    resolve_diff_base,
    source_languages,
    validate_inventory,
)
from .policy import (
    MODULE_CONTRACTS_ID,
    CheckDef,
    Config,
    ConfigError,
    GateError,
    UnsupportedError,
    UsageError,
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
    CheckDeadline,
    Diagnostics,
    RunTimeout,
    check_deadline,
    mark_step,
    remaining_budget,
)


RATCHET_BUDGET_SECONDS = 600
RUN_ALLOWANCE_SECONDS = 300


class RunCleanupError(UsageError):
    """The run directory could not be removed after the checks ran."""


def _budget_detail(
    reason: str,
    start: float,
    budget: float,
    *,
    already_detailed: bool = False,
) -> str:
    if already_detailed and "deadline:" in reason:
        return reason
    elapsed = time.monotonic() - start
    return f"{reason} (timeout; deadline: {budget:g} seconds; elapsed: {elapsed:.3f} seconds)"


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
    tests_ran: int | None = None
    tests_skipped: int | None = None
    satisfied: bool | None = None
    caused_by: list[str] | None = None
    reason: str | None = None
    diagnostics: Diagnostics = field(default_factory=Diagnostics)
    evidence_path: Path | None = None
    adapter_data: Any = None
    configuration_error: bool = False
    tool: dict[str, str] | None = None
    report_fields: dict[str, Any] = field(default_factory=dict)
    excluded_lines: dict[str, tuple[int, ...]] | None = None
    resolved_base: str | None = None

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
            "caused_by": self.caused_by,
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
        if self.tool is not None:
            document["tool"] = self.tool
        document.update(self.report_fields)
        if self.measurement is not None:
            document["measurement"] = self.measurement
        return document

    def _location_coverage(self) -> str:
        coverage = location_coverage(self.adapter)
        if coverage == "complete" and _incomplete_locations(self):
            return "partial"
        return coverage


def location_coverage(adapter: str) -> str:
    from .adapters import adapter_for

    descriptor = adapter_for(adapter)
    return descriptor.location_coverage if descriptor is not None else "none"


def _incomplete_locations(result: CheckResult) -> bool:
    return result.ratchet is not None and any(
        item.locations is None for item in result.ratchet.findings
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
    if check.baseline is None:
        return []
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


def _check_result(
    check: CheckDef,
    start: float | None,
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
        duration_seconds=time.monotonic() - start if start is not None else 0.0,
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
    mark_step("ratchet evaluation")
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
                direction=check.direction,
            ),
            None,
        )
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, "unsupported"
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, "error"


def _adapter_selection(
    context: AdapterContext,
) -> tuple[Any, float, list[str], list[str]]:
    check = context.check
    spec = check.spec
    start = time.monotonic()
    mark_step("file selection")
    selected, names = _select_files(
        context.config, check, context.files, context.classes
    )
    return spec, start, selected, names


def _ratchet_reason(
    ratchet: RatchetResult | None,
    reason: str | None,
    execution: str,
    start: float,
) -> str | None:
    if reason is None:
        outcome = ratchet.outcome if ratchet is not None else None
        if outcome not in (None, "pass"):
            return "ratchet findings did not satisfy the threshold or baseline"
        return reason
    if execution == "budget":
        return _budget_detail(
            reason,
            start,
            RATCHET_BUDGET_SECONDS,
            already_detailed=True,
        )
    return reason


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
        budget_seconds=RATCHET_BUDGET_SECONDS,
        findings=ratchet.findings if ratchet is not None else [],
        resolved_baseline_entries=ratchet.resolved if ratchet is not None else [],
        unmeasured_baseline_entries=(
            ratchet.unmeasured if ratchet is not None else []
        ),
        satisfied=ratchet.satisfied if ratchet is not None else None,
        ratchet=ratchet,
        measurement=measurement,
        diagnostics=diagnostics or Diagnostics(),
        reason=_ratchet_reason(ratchet, reason, execution, start),
    )


def _finish_ratchet(
    check: CheckDef,
    findings: list[Any],
    entries: list[Any],
    prefix: str,
    start: float,
    domain: Domain,
    message: str,
    measurement: dict[str, Any] | None = None,
) -> CheckResult:
    ratchet, failure = _evaluate_ratchet(
        findings, entries, check, prefix, domain
    )
    if ratchet is None:
        outcome = failure or "error"
        measurement = None
    else:
        outcome = ratchet.outcome
    result = _ratchet_result(
        check,
        start,
        outcome,
        ratchet=ratchet,
        measurement=measurement,
        reason=failure,
    )
    if ratchet is not None and ratchet.satisfied:
        print(f"{prefix}: {message}", flush=True)
    return result


def _finish_crap_ratchet(
    check: CheckDef,
    findings: list[Any],
    prefix: str,
    start: float,
    domain_for: Any,
    nouns: tuple[str, str],
) -> CheckResult:
    try:
        mark_step("baseline loading")
        entries = _baseline_entries(check)
    except GateError as error:
        return _ratchet_error(check, start, prefix, error)
    noun = nouns[1] if len(findings) == 1 else nouns[0]
    return _finish_ratchet(
        check,
        findings,
        entries,
        prefix,
        start,
        domain_for(entries),
        f"{len(findings)} {noun} within threshold",
        measurement={"functions": len(findings)},
    )


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


def _configuration_error(
    check: CheckDef, start: float, prefix: str, error: Exception
) -> CheckResult:
    """The check could not measure because its configuration or input is unusable."""
    result = _ratchet_error(check, start, prefix, error)
    result.configuration_error = True
    return result


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
    report: bool = True,
    **fields: Any,
) -> CheckResult:
    if execution == "budget":
        reason = _budget_detail(reason, start, spec.budget_seconds)
    if report:
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
    requires: str | None,
    earlier: Iterable[CheckDef | CheckResult],
) -> list[str]:
    """The configured test check, or every earlier check producing tests."""
    if requires is not None:
        return [requires]
    return [
        check.id for check in earlier
        if "tests" in check.evidence
    ]


def _require_distinct(command: str, identifiers: list[str]) -> None:
    seen: set[str] = set()
    for identifier in identifiers:
        if identifier in seen:
            raise UsageError(f"qg.py {command}: duplicate check id {identifier!r}")
        seen.add(identifier)


def _required(config: Config, check: CheckDef) -> list[str]:
    return list(check.required)


def _needed_order(config: Config, selected: list[CheckDef]) -> list[str]:
    needed = {check.id for check in selected}
    for check in reversed(list(config.checks.values())):
        if check.id in needed:
            needed.update(_required(config, check))
    return _policy_order(config, needed)


def _policy_order(config: Config, needed: set[str]) -> list[str]:
    return [identifier for identifier in config.checks if identifier in needed]


def _check_descriptor(check: CheckDef) -> AdapterDescriptor:
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
    evidence_dir: Path,
    prior: dict[str, CheckResult],
    base_override: DiffBaseOverride | None = None,
    selection: CheckSelection | None = None,
    graph_cache: GraphCache | None = None,
) -> CheckResult:
    context = AdapterContext(
        root, config, check, files if selection is None else selection.files,
        classes, prefix, prior, evidence_dir, base_override, selection, inventory_files=files,
        graph_cache=graph_cache,
    )
    return _check_descriptor(check).run(context)


def run_check(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    *,
    prefix: str,
    evidence_dir: Path,
    prior: dict[str, CheckResult] | None = None,
    base_override: DiffBaseOverride | None = None,
    selection: CheckSelection | None = None,
    graph_cache: GraphCache | None = None,
) -> CheckResult:
    _check_descriptor(check)
    start = time.monotonic()
    with check_deadline(check.id, start, _check_budget(check)):
        result = _adapter_runner(
            root, config, check, files, classes, prefix, evidence_dir,
            prior or {}, base_override, selection, graph_cache,
        )
    result.duration_seconds = time.monotonic() - start
    return result


def _check_budget(check: CheckDef) -> float:
    return _check_descriptor(check).budget(check.spec)


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
    encoded = "\n".join(messages).encode("utf-8", errors="backslashreplace")
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
) -> tuple[int, list[str], dict[str, str], list[str], str, float, list[str] | None]:
    start = time.monotonic()
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        message = f"inventory: {error}"
        print(message, file=sys.stderr)
        argv = getattr(error, "argv", None)
        return 1, [], {}, [message], "error", time.monotonic() - start, argv
    if violations:
        messages = [f"inventory: {violation}" for violation in violations]
        for message in messages:
            print(message, file=sys.stderr)
        return 1, files, classes, messages, "completed", time.monotonic() - start, None
    print(f"inventory: {len(files)} files match {len(config.rules)} rules")
    return 0, files, classes, [], "completed", time.monotonic() - start, None


def _prune_option_error(
    root: Path, config: Config, requested: list[str], message: str
) -> tuple[int, dict[str, Any]]:
    print(message, file=sys.stderr)
    return 2, gate_result.error_document(
        root,
        config.path,
        message,
        loaded_digest=config.policy_sha256,
        prune={
            "requested": requested,
            "performed": False,
            "reason": message,
        },
    )


def _run_limit(selected_checks: Iterable[CheckDef], *, contract_extraction: bool = False) -> float:
    """In-process analysis takes time even over bounded inputs, so the run
    allowance lets a subprocess exhaust its own budget and end the check.
    The run timer starts before any subprocess, so a limit of exactly the
    check budgets would always fire first for a hanging last check.
    """
    return (
        sum(_check_budget(check) for check in selected_checks)
        + RATCHET_BUDGET_SECONDS * contract_extraction
        + RUN_ALLOWANCE_SECONDS
    )


def _arm_run_limit(limit: float) -> Any:
    def handler(_signum: int, _frame: Any) -> None:
        raise RunTimeout(limit, RUN_ALLOWANCE_SECONDS)

    previous = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, limit)
    return previous


def _disarm_run_limit(previous: Any) -> None:
    signal.setitimer(signal.ITIMER_REAL, 0.0)
    signal.signal(signal.SIGALRM, previous)


def _run_cleanup_message(directory: Any, error: OSError) -> str:
    return f"check: cannot remove the run directory {directory.name}: {error}"


def _remove_run_directory(directory: Any, *, report: bool = False) -> None:
    try:
        directory.cleanup()
    except OSError as error:
        message = _run_cleanup_message(directory, error)
        if report:
            print(message, file=sys.stderr)
        else:
            raise RunCleanupError(message) from error


TEMPORARY_PATH_LIMIT = 10


def _temporary_test_directory() -> Path:
    """Create the fresh directory a test suite receives as TMPDIR."""
    try:
        return Path(tempfile.mkdtemp(prefix="qg-t-"))
    except OSError as error:
        raise UsageError(
            f"cannot create the temporary directory: {error}"
        ) from error


def _temporary_paths(directory: Path) -> list[str]:
    """Every path left under DIRECTORY, relative to it and sorted."""
    paths: list[str] = []

    def fail(error: OSError) -> None:
        raise error

    for current, directories, files in os.walk(directory, onerror=fail):
        base = Path(current)
        paths.extend(
            str((base / name).relative_to(directory))
            for name in (*directories, *files)
        )
    return sorted(paths)


def _temporary_count(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _temporary_entries(paths: list[str]) -> list[tuple[str, int]]:
    """The entries PATHS left in the suite's TMPDIR, with their path counts."""
    counts: dict[str, int] = {}
    for relative in paths:
        entry = relative.split(os.sep, 1)[0]
        counts[entry] = counts.get(entry, 0) + 1
    return sorted(counts.items())


def _temporary_entry_text(name: str, count: int) -> str:
    if count == 1:
        return name
    return f"{name} ({_temporary_count(count, 'path', 'paths')})"


def _temporary_reason(paths: list[str]) -> str | None:
    if len(paths) > 0:
        entries = _temporary_entries(paths)
        shown = ", ".join(
            _temporary_entry_text(name, count)
            for name, count in entries[:TEMPORARY_PATH_LIMIT]
        )
        more = len(entries) - TEMPORARY_PATH_LIMIT
        if more > 0:
            shown = f"{shown}, and {more} more"
        return (
            f"{_temporary_count(len(entries), 'entry', 'entries')} "
            f"({_temporary_count(len(paths), 'path', 'paths')}) "
            f"left in the suite's TMPDIR: {shown}"
        )
    return None


def _remove_temporary_directory(directory: Path) -> str | None:
    from .tools import _make_directories_writable

    if not os.path.lexists(directory):
        return None
    try:
        _make_directories_writable(directory)
        shutil.rmtree(directory)
    except OSError as error:
        return f"cannot remove the temporary directory {directory}: {error}"
    return None


def _finish_temporary(directory: Path) -> list[str]:
    """List the paths left in DIRECTORY, then remove it."""
    paths: list[str] = []
    listing_error: str | None = None
    try:
        paths = _temporary_paths(directory)
    except OSError as error:
        listing_error = f"cannot list the temporary directory {directory}: {error}"
    removal_error = _remove_temporary_directory(directory)
    if removal_error is not None:
        raise UsageError(removal_error)
    if listing_error is not None:
        raise UsageError(listing_error)
    return paths


def _combined_reason(first: str | None, second: str | None) -> str | None:
    if second is None:
        return first
    if first is None:
        return second
    return f"{first}; {second}"


def _merge_temporary_reason(
    result: CheckResult, temporary_reason: str | None
) -> CheckResult:
    """Fold a leftover-path reason into a finished check result."""
    if temporary_reason is None:
        return result
    result.reason = _combined_reason(result.reason or None, temporary_reason)
    if result.outcome == "pass":
        result.outcome = "fail"
    return result


def _finish_test_result(
    result: CheckResult,
    temporary_reason: str | None,
    prefix: str,
    combined: str | None = None,
) -> CheckResult:
    """Report a finished test result, including any temporary-path reason."""
    result = _merge_temporary_reason(result, temporary_reason)
    if result.reason is not None:
        print(f"{prefix}: {result.reason}", file=sys.stderr)
    if combined is not None:
        _print_output(prefix, combined)
    return result


@dataclass
class CheckSelection:
    selected: dict[str, str]
    left_out: dict[str, str]
    reason: str
    skip: bool = False
    full_suite: str | None = None
    files: list[str] = field(default_factory=list)
    adapter_report: bool = False

    def report(self) -> dict[str, Any]:
        return {"selected": self.selected.copy(), "left_out": self.left_out.copy(), "reason": self.reason}


OUTSIDE_SCOPE = "no changed file affects this input"
RUNTIME_SUITE_REASON = "full run: suite runtime inputs are undeclared"


def _command_suite(check: CheckDef) -> bool:
    return check.adapter == "command" and "tests" in check.evidence


def _file_selection_mode(check: CheckDef) -> Literal["expanded", "affected"] | None:
    if check.adapter == "command" and not _command_suite(check):
        if any(map(is_files_argument, check.spec.run)):
            return "affected"
    return _check_descriptor(check).file_selection


def _global_input(config: Config, classes: dict[str, str], changed: frozenset[str]) -> str | None:
    for path in sorted(changed):
        if path in {"quality-gate.toml", "tools.lock.toml"}:
            return f"full run: configuration input {path} changed"
        if path not in classes and sum(fnmatchcase(path, rule.pattern) for rule in config.rules) != 1:
            return f"full run: cannot attribute changed file {path}"
    return None


def _selection_inputs(
    root: Path, config: Config, files: list[str], classes: dict[str, str],
    evidence_dir: Path, changed: frozenset[str], graph_cache: GraphCache,
) -> tuple[dict[str, str], dict[str, str], str | None]:
    full = _global_input(config, classes, changed)
    if full or not changed:
        return {}, {}, full
    try:
        with check_deadline("affected scope", time.monotonic(), RATCHET_BUDGET_SECONDS):
            nodes, expanded, affected = affected_graph(
                root, config, files, classes, evidence_dir, set(changed), graph_cache,
            )
    except (GateError, ValueError, RecursionError) as error:
        return {}, {}, f"full run: module graph unavailable ({error})"
    unplaced = sorted(changed - nodes)
    return expanded, affected, f"full run: unplaced file {unplaced[0]}" if unplaced else None


def _forced_inputs(config: Config, selected: list[CheckDef]) -> dict[str, str]:
    return {
        identifier: f"full run: required by {check.id}"
        for check in selected if check.adapter == "verification"
        for identifier in _needed_order(config, [check])
        if identifier != check.id
    }


def _file_scope(
    check: CheckDef, files: list[str], expanded: dict[str, str],
    affected: dict[str, str], full: str | None,
) -> CheckSelection:
    mode = _file_selection_mode(check)
    if mode is None:
        reason = full or "full run"
        return CheckSelection(
            dict.fromkeys(files, reason), {}, reason, files=files,
            adapter_report=check.adapter in {"python_shape", "module_tree"},
        )
    if full is not None:
        reason = full if files else f"{full} (no files in the input class)"
        return CheckSelection(dict.fromkeys(files, full), {}, reason, skip=not files, files=files)
    reasons = expanded if mode == "expanded" else affected
    return _affected_file_scope(files, reasons)


def _affected_file_scope(files: list[str], reasons: dict[str, str]) -> CheckSelection:
    paths = set(files)
    selected = {path: reasons[path] for path in sorted(paths & reasons.keys())}
    left_out = dict.fromkeys(sorted(paths - reasons.keys()), OUTSIDE_SCOPE)
    reason = "affected files" if selected else OUTSIDE_SCOPE
    return CheckSelection(selected, left_out, reason, skip=not selected, files=list(selected))


def _elisp_suite_scope(path: str, reason: str | None, files: list[str]) -> CheckSelection:
    if reason is None:
        return CheckSelection({}, {path: OUTSIDE_SCOPE}, OUTSIDE_SCOPE, skip=True)
    return CheckSelection({path: reason}, {}, reason, files=files)


def _check_selection(
    check: CheckDef, inputs: list[str], expanded: dict[str, str], affected: dict[str, str],
    full: str | None, runtime_reason: str | None,
) -> CheckSelection:
    suite_reason = full or runtime_reason
    if check.adapter == "elisp_tests":
        return _elisp_suite_scope(Path(check.spec.suite).as_posix(), suite_reason, inputs)
    if check.adapter == "python_tests":
        return CheckSelection(
            {}, {}, suite_reason or "full run", full_suite=suite_reason, files=inputs, adapter_report=True,
        )
    if _command_suite(check):
        reason = "full run: command adapter suite is opaque"
        return CheckSelection({}, {}, reason, files=inputs)
    return _file_scope(check, inputs, expanded, affected, full)


def _affected_selection(
    root: Path, config: Config, files: list[str], classes: dict[str, str],
    evidence_dir: Path, changed: frozenset[str], checks: list[CheckDef],
    graph_cache: GraphCache,
) -> dict[str, CheckSelection]:
    expanded, affected, full = _selection_inputs(
        root, config, files, classes, evidence_dir, changed, graph_cache,
    )
    forced = _forced_inputs(config, checks)
    runtime_reason = RUNTIME_SUITE_REASON if changed else None
    selections = {}
    for check in checks:
        inputs = _select_files(config, check, files, classes)[0]
        selections[check.id] = _check_selection(
            check, inputs, expanded, affected, full or forced.get(check.id), runtime_reason,
        )
    return selections


def _record_check_selection(
    result: CheckResult, selection: CheckSelection | None, planned_report: dict[str, Any] | None,
) -> None:
    if planned_report is not None:
        result.report_fields["selection"] = planned_report
    elif selection is not None:
        result.report_fields.setdefault("selection", selection.report())


def _run_selected_check(
    root: Path, config: Config, check: CheckDef, files: list[str],
    classes: dict[str, str], evidence_dir: Path, prior: dict[str, CheckResult],
    base_override: DiffBaseOverride, selection: CheckSelection | None, graph_cache: GraphCache,
) -> CheckResult:
    prefix = f"check: {check.id}"
    planned_report = selection.report() if selection is not None and not selection.adapter_report else None
    if selection is not None and selection.skip:
        result = _check_result(
            check, None, "not_run", execution="not_run",
            reason=selection.reason, satisfied=True,
        )
        print(f"{prefix}: not run ({selection.reason})")
    else:
        print(f"{prefix} ({check.adapter})", flush=True)
        result = run_check(
            root, config, check, files, classes, prefix=prefix, evidence_dir=evidence_dir,
            prior=prior, base_override=base_override, selection=selection, graph_cache=graph_cache,
        )
    _record_check_selection(result, selection, planned_report)
    return result


def _scope_selections(
    root: Path, config: Config, files: list[str], classes: dict[str, str],
    evidence_dir: Path, changed: frozenset[str] | None, checks: list[CheckDef], inventory_code: int,
    graph_cache: GraphCache,
) -> dict[str, CheckSelection]:
    if changed is None or not checks:
        return {}
    if inventory_code != 0:
        return {check.id: CheckSelection({}, {}, "inventory failed") for check in checks}
    return _affected_selection(
        root, config, files, classes, evidence_dir, changed, checks, graph_cache,
    )


def _run_inventory_blocked_check(check: CheckDef, selection: CheckSelection | None) -> CheckResult:
    result = _skipped(check)
    print(f"check: {check.id}: {result.reason}", file=sys.stderr)
    if selection is None and check.adapter == "module_tree":
        selection = CheckSelection({}, {}, "inventory failed")
    if selection is not None:
        result.report_fields["selection"] = selection.report()
    return result


def _contract_message(finding: dict) -> str:
    if finding["rule"] == "module-interface":
        edge = finding["edge"]
        failed = ", ".join(finding["failed_conditions"])
        permitted = json.dumps(finding["permitted_entry_points"], ensure_ascii=False)
        return (
            f"module-interface: {edge['source']}:{edge['line']} -> {edge['target']} ({edge['kind']}), "
            f"{finding['source_module']} -> {finding['target_module']}: {failed}; "
            f"permitted entry points: {permitted}"
        )
    location = f"{finding['file']}:{finding['line']}: " if "line" in finding else ""
    return f"{finding['rule']}: {location}{finding['message']}"


def _require_contract_budget() -> None:
    if remaining_budget(RATCHET_BUDGET_SECONDS) <= 0:
        raise TimeoutError("module contract budget exceeded")


def _contract_extraction_error(
    error: Exception, deadline: CheckDeadline, partial: DependencyEvidence, findings: list[dict],
) -> tuple[dict | None, str]:
    message = str(error)
    execution = "error"
    if remaining_budget(deadline.seconds) <= 0:
        message = _budget_detail(f"{deadline.step}: {message}", deadline.started, deadline.seconds)
        execution = "budget"
    findings.append({"rule": "module-extraction", "stage": deadline.step, "message": message})
    return (partial.report() if partial.reader_refusals else None), execution


def _extract_module_contracts(
    root: Path, config: Config, owners: dict[str, str], classes: InventoryClasses, evidence_dir: Path,
    findings: list[dict], *, inventory_files: list[str], graph_cache: GraphCache | None,
) -> tuple[dict | None, str]:
    start = time.monotonic()
    budget = RATCHET_BUDGET_SECONDS
    partial = DependencyEvidence(python_import_roots=config.python_import_roots)
    with check_deadline("module-contracts", start, budget) as deadline:
        try:
            mark_step("module graph inputs")
            _require_contract_budget()
            graph = extract_contract_graph(
                root, config, owners, classes, evidence_dir, partial,
                inventory_files=inventory_files, graph_cache=graph_cache,
            )
            _require_contract_budget()
            mark_step("module interface evaluation")
            findings.extend(module_contract_findings(config, owners, graph, classes.tracked_code_paths))
            _require_contract_budget()
        except RunTimeout:
            raise
        except (GateError, ValueError, TimeoutError, RecursionError) as error:
            return _contract_extraction_error(error, deadline, partial, findings)
        finally:
            findings[:0] = [{"rule": "module-extraction", **row} for row in partial.reader_refusals]
    return graph.report(), "completed"


def _tree_entry_modes(root: Path, commit: str, paths: Iterable[str]) -> dict[str, str]:
    raw = _git(
        root, ["--literal-pathspecs", "ls-tree", "-t", "-z", "--full-tree", commit, "--", *paths],
        "base tree inspection",
    )
    entries = {}
    for record in _split_nul(raw):
        metadata, _, path = record.partition("\t")
        entries[path] = metadata.split()[0]
    return entries


def _validate_protected_tree(root: Path, config: Config, base: DiffBase) -> None:
    declarations = {
        path: f"modules.{name}.protected_paths[{index}]"
        for name, module in config.modules.items()
        for index, path in enumerate(module.protected_paths)
    }
    if not declarations:
        return
    modes = _tree_entry_modes(root, base.commit, declarations)
    entry_kinds = {None: "no entry for", "040000": "directory", "120000": "symlink", "160000": "gitlink"}
    for path, item in declarations.items():
        mode = modes.get(path)
        if mode not in ("100644", "100755"):
            kind = entry_kinds[mode]
            raise ConfigError(
                f"{config.path}: {item}: expected a regular file in diff base {base.commit}, "
                f"got {kind} {path!r}"
            )


def _shared_changed_paths(
    root: Path, config: Config, diff: DiffBaseOverride,
) -> tuple[set[str] | frozenset[str], str | None]:
    if config.shared_base is None:
        return frozenset(), None
    try:
        base = diff.for_scope(root, config.shared_base)
        _validate_protected_tree(root, config, base)
        if diff.changed_paths is not None:
            return diff.changed_paths, base.commit
        return changed_paths(root, base.commit, "changed-file selection"), base.commit
    except UsageError:
        raise
    except GateError as error:
        raise UsageError(f"module-contracts: {error}") from error


def _shared_entry_point_findings(
    config: Config, owners: dict[str, str], changed: set[str] | frozenset[str],
) -> list[dict]:
    protected = {path for module in config.modules.values() for path in module.protected_paths}
    edited_protected = sorted(protected.intersection(changed))
    features = sorted((changed - protected).intersection(owners))
    return [
        {"rule": "shared-entry-point", "file": feature, "module": owners[feature],
         "protected_path": path,
         "message": f"{feature} changes with protected path {path}. Put the registration or "
                    f"documentation beside {feature} in module {owners[feature]}."}
        for feature in features for path in edited_protected
    ]


def _inventory_blocked_contracts(
    config: Config, files: list[str], classes: dict[str, str], changed: set[str] | frozenset[str],
) -> tuple[str, dict[str, str]]:
    skipped = "skipped" if config.shared_base is None else "graph checks skipped"
    message = f"module-contracts: {skipped} because inventory failed"
    owners = {}
    if changed and isinstance(classes, InventoryClasses):
        owners, _ = module_ownership(config, files, classes)
    return message, owners


def _run_module_contracts(
    root: Path, config: Config, files: list[str], classes: dict[str, str],
    inventory_code: int, evidence_dir: Path, diff: DiffBaseOverride, graph_cache: GraphCache | None = None,
) -> CheckResult:
    print("check: module-contracts", flush=True)
    start = time.monotonic()
    findings: list[dict] = []
    execution = "completed"
    measurement = None
    budget = None
    messages = []
    changed, resolved_base = _shared_changed_paths(root, config, diff)
    if inventory_code != 0:
        execution = "error"
        message, owners = _inventory_blocked_contracts(config, files, classes, changed)
        messages.append(message)
    else:
        assert isinstance(classes, InventoryClasses)
        owners, findings = module_ownership(config, files, classes)
        if not findings and len(config.modules) >= 2:
            budget = RATCHET_BUDGET_SECONDS
            measurement, execution = _extract_module_contracts(
                root, config, owners, classes, evidence_dir, findings, inventory_files=files,
                graph_cache=graph_cache,
            )
    findings.extend(_shared_entry_point_findings(config, owners, changed))
    messages.extend(f"module-contracts: {_contract_message(row)}" for row in findings)
    for message in messages:
        print(message, file=sys.stderr)
    result = _builtin_result(
        "module-contracts", ok=not messages, duration_seconds=time.monotonic() - start,
        messages=messages, execution=execution, argv=None,
    )
    result.findings = findings
    result.budget_seconds = budget
    result.resolved_base = resolved_base
    result.measurement = measurement
    return result


@dataclass
class LedgerRun:
    destination: Path
    supplied: str
    run_id: str | None = None
    selected: list[str] | None = None
    affected_base: str | None = None
    diff: DiffBaseOverride = field(default_factory=DiffBaseOverride)
    start: dict[str, Any] = field(default_factory=lambda: {"revision": None, "dirty": None})
    interrupted: dict[str, Any] | None = None

    @contextlib.contextmanager
    def dispatch(self, identifier: str, check: CheckDef | None):
        started = time.monotonic()
        try:
            yield
        except BaseException as error:
            self.interrupted = {
                "id": identifier,
                "adapter": check.adapter if check else identifier,
                "metric_version": check.metric_version if check else f"{identifier}/1",
                "execution": "interrupted",
                "outcome": None,
                "satisfied": None,
                "duration_seconds": round(time.monotonic() - started, 6),
                "termination": type(error).__name__,
            }
            raise


def _begin_ledger(
    ledger: LedgerRun, root: Path, selected: list[str] | None, affected_base: str | None,
) -> None:
    ledger.selected = selected
    ledger.affected_base = affected_base
    ledger.run_id = str(uuid.uuid4())
    ledger.start = gate_result.consumer_identity(root, strict=True)


def _dispatch_attempt(ledger: LedgerRun | None, identifier: str, check: CheckDef | None = None):
    return ledger.dispatch(identifier, check) if ledger is not None else contextlib.nullcontext()


def _dispatch_module_contracts(
    root: Path, config: Config, files: list[str], classes: dict[str, str], inventory_code: int,
    directory: Path, diff: DiffBaseOverride, ledger: LedgerRun | None, results: list[CheckResult],
    graph_cache: GraphCache,
) -> None:
    with _dispatch_attempt(ledger, "module-contracts"):
        evidence_dir = directory / "module-contracts"
        evidence_dir.mkdir()
        result = _run_module_contracts(
            root, config, files, classes, inventory_code, evidence_dir, diff, graph_cache,
        )
        results.append(result)
    if diff.changed_paths is not None:
        result.report_fields["selection"] = _builtin_selection(files, inventory_code)


def _run_configured_check(
    root: Path, config: Config, check: CheckDef, files: list[str], classes: dict[str, str],
    directory: Path, prior: dict[str, CheckResult], diff: DiffBaseOverride,
    selection: CheckSelection | None, inventory_code: int, graph_cache: GraphCache,
) -> CheckResult:
    if inventory_code != 0:
        return _run_inventory_blocked_check(check, selection)
    evidence_dir = directory / check.id
    evidence_dir.mkdir()
    return _run_selected_check(
        root, config, check, files, classes, evidence_dir, prior, diff, selection, graph_cache,
    )


def _read_only_graph_check(check: CheckDef) -> bool:
    return check.adapter in {"module_graph", "module_tree"}


def _snapshot_graph_languages(root: Path, config: Config, classes: dict[str, str], cache: GraphCache) -> None:
    """Resolve deferred inventory languages before a check can change the checkout."""
    if not isinstance(classes, InventoryClasses):
        return
    for path in sorted(classes.deferred_links):
        try:
            source_languages(root, [path], config, classes)
        except GateError as error:
            cache.classification_errors[path] = error


def _policy_graph_cache(
    root: Path, config: Config, classes: dict[str, str], inventory_code: int,
    checks: list[CheckDef], diff: DiffBaseOverride, module_contracts: bool,
) -> GraphCache:
    cache = GraphCache()
    if inventory_code != 0:
        return cache
    if module_contracts or diff.changed_paths is not None or any(map(_read_only_graph_check, checks)):
        _snapshot_graph_languages(root, config, classes, cache)
    return cache


def _dispatch_configured_checks(
    root: Path, config: Config, files: list[str], classes: dict[str, str], inventory_code: int,
    checks: list[CheckDef], diff: DiffBaseOverride, directory: Path, graph_cache: GraphCache,
    results: list[CheckResult], ledger: LedgerRun | None,
) -> None:
    selections = _scope_selections(
        root, config, files, classes, directory, diff.changed_paths, checks, inventory_code, graph_cache,
    )
    prior: dict[str, CheckResult] = {}
    for check in checks:
        with _dispatch_attempt(ledger, check.id, check):
            outcome = _run_configured_check(
                root, config, check, files, classes, directory, prior, diff,
                selections.get(check.id), inventory_code, graph_cache,
            )
            results.append(outcome)
        if not _read_only_graph_check(check):
            graph_cache.clear()
        prior[check.id] = outcome


def _policy_results(
    root: Path, config: Config, files: list[str], classes: dict[str, str], inventory_code: int,
    selected_checks: list[CheckDef], base_override: DiffBaseOverride | None,
    directory: Path, module_contracts: bool,
    *, results: list[CheckResult] | None = None, ledger: LedgerRun | None = None,
) -> list[CheckResult]:
    if results is None:
        results = []
    if base_override is None:
        base_override = resolve_diff_base(root)
    if ledger is not None:
        ledger.diff = base_override
    graph_cache = _policy_graph_cache(
        root, config, classes, inventory_code, selected_checks, base_override, module_contracts,
    )
    if module_contracts:
        _dispatch_module_contracts(
            root, config, files, classes, inventory_code, directory, base_override, ledger,
            results, graph_cache,
        )
    _dispatch_configured_checks(
        root, config, files, classes, inventory_code, selected_checks, base_override, directory,
        graph_cache, results, ledger,
    )
    return results


def _run_policy_checks(
    root: Path,
    config: Config,
    files: list[str],
    classes: dict[str, str],
    inventory_code: int,
    selected_ids: list[str] | None = None,
    *,
    base_override: DiffBaseOverride | None = None,
    module_contracts: bool = False,
    results: list[CheckResult] | None = None,
    ledger: LedgerRun | None = None,
) -> list[CheckResult]:
    selected = list(config.checks) if selected_ids is None else selected_ids
    selected_checks = [config.checks[identifier] for identifier in selected]
    run_directory = tempfile.TemporaryDirectory(prefix="qg-run-")
    contract_extraction = module_contracts and inventory_code == 0 and len(config.modules) >= 2
    previous = _arm_run_limit(_run_limit(selected_checks, contract_extraction=contract_extraction))
    try:
        try:
            results = _policy_results(
                root, config, files, classes, inventory_code, selected_checks,
                base_override, Path(run_directory.name), module_contracts, results=results, ledger=ledger,
            )
        except BaseException:
            _remove_run_directory(run_directory, report=True)
            raise
        else:
            _remove_run_directory(run_directory)
    finally:
        _disarm_run_limit(previous)
    return results


def _write_pruned(
    check: CheckDef,
    result: CheckResult,
    destination: Path,
) -> tuple[bool, str | None]:
    try:
        assert result.ratchet is not None
        entries = pruned_entries(result.ratchet)
        write_baseline(
            destination,
            entries,
            check_id=check.id,
            metric_version=check.metric_version,
        )
    except GateError as error:
        print(f"check: {check.id}: {error}", file=sys.stderr)
        return False, str(error)
    if entries:
        print(f"check: {check.id}: baseline updated at {destination}")
    else:
        print(f"check: {check.id}: baseline is now empty at {destination}")
    return True, None


def _prune_refusal(prune_id: str, requested: list[str]) -> dict[str, Any]:
    reason = "the check did not pass; nothing written"
    print(
        f"check: {prune_id}: prune refused because the check did not "
        "pass; nothing written",
        file=sys.stderr,
    )
    return {"requested": requested, "performed": False, "reason": reason}


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
) -> dict[str, Any]:
    if not requested:
        return {"requested": [], "performed": False, "reason": None}
    ids = _expand_prune_ids(config, requested)
    refusal = _prune_targets_refusal(results, ids, requested)
    if refusal is not None:
        return refusal
    return _write_prune_set(
        config, results, requested, _prune_destinations(config, ids)
    )


def _write_prune_set(
    config: Config, results: list[CheckResult], requested: list[str],
    destinations: list[tuple[str, Path]],
) -> dict[str, Any]:
    for identifier, destination in destinations:
        target = _prune_check_result(results, identifier)
        performed, reason = _write_pruned(
            config.checks[identifier], target, destination
        )
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
    for result in results:
        if not result.is_satisfied():
            return result
    return None


def _prune_destinations(
    config: Config, ids: list[str]
) -> list[tuple[str, Path]]:
    destinations = []
    for identifier in ids:
        check = config.checks[identifier]
        assert check.baseline is not None
        destinations.append((identifier, check.baseline))
    return destinations


def _builtin_failures(results: list[CheckResult]) -> list[str]:
    return [
        result.id
        for result in results
        if result.kind in BUILTIN_RESULT_KINDS
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


def _failure_entries(
    results: list[CheckResult], obligations: list[dict[str, Any]]
) -> list[tuple[str, list[str] | None]]:
    """Every reported failure, with its root checks or null when it is a root."""
    by_id = {result.id: result for result in results}
    entries = [
        (identifier, by_id[identifier].caused_by)
        for identifier in _failed_check_ids(results)
    ]
    entries.extend(
        (f"obligation {item['class']} tier {item['tier']}", item["caused_by"])
        for item in obligations
        if item["status"] == "unsatisfied"
    )
    return entries


def _rejection_lines(
    results: list[CheckResult], obligations: list[dict[str, Any]]
) -> list[str]:
    """A consequences line when there is one, then the rejection summary."""
    entries = _failure_entries(results, obligations)
    roots: list[str] = []
    consequences: list[str] = []
    for name, caused_by in entries:
        if caused_by is None:
            roots.append(name)
        else:
            consequences.append(f"{name} because {', '.join(caused_by)}")
    lines = []
    if consequences:
        lines.append(f"check: consequences ({'; '.join(consequences)})")
    lines.append(f"check: failed ({', '.join(roots)})")
    return lines


def _assign_causes(config: Config, results: list[CheckResult]) -> None:
    causes = gate_result.check_causes(config, results)
    for result in results:
        result.caused_by = causes[result.id]


def _result_document(
    root: Path,
    config: Config,
    decision: str,
    results: list[CheckResult],
    obligations: list[dict[str, Any]],
    prune: dict[str, Any],
    selected: list[str] | None = None,
) -> dict[str, Any]:
    document = {
        "schema": 3,
        "gate_version": gate_result.gate_version(),
        **gate_result.consumer_identity(root),
        "policy_sha256": config.policy_sha256,
        "decision": decision,
        "checks": [result.to_json() for result in results],
        "obligations": obligations,
        "prune": prune,
    }
    if selected is not None:
        document["selected"] = list(selected)
    return document


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
    for identifier in requested:
        problem = _prune_id_problem(config, identifier)
        if problem is not None:
            return problem
    return None


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
        argv,
    ) = _run_inventory(root, config)
    result = _builtin_result(
        "inventory",
        ok=inventory_code == 0,
        duration_seconds=inventory_duration,
        messages=inventory_messages,
        execution=inventory_execution,
        argv=argv,
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
        argv=hygiene.argv,
    )

DECISION_MESSAGES = {
    "accepted": "check: passed",
    "accepted_with_exceptions": "check: passed with exceptions",
    "partial": "check: partial run passed",
}


def _print_unevaluated_obligations(obligations: list[dict[str, Any]]) -> None:
    unevaluated = [
        f"{json.dumps(item['class'])} tier {item['tier']}"
        for item in obligations
        if item["status"] == "not_evaluated"
    ]
    if unevaluated:
        print(f"check: obligations not evaluated ({', '.join(unevaluated)})", flush=True)


def _print_check_report(
    document: dict[str, Any], results: list[CheckResult], notices: list[str],
) -> None:
    decision = document["decision"]
    obligations = document["obligations"]
    _print_unevaluated_obligations(obligations)
    if notices:
        print(*notices, sep="\n", file=sys.stderr)
    elif decision == "error":
        print(f"check: error: {document.get('error')}", file=sys.stderr)
    elif decision == "rejected":
        print(*_rejection_lines(results, obligations), sep="\n", file=sys.stderr)
    else:
        print(f"{DECISION_MESSAGES[decision]} ({len(results)} checks)", flush=True)


def _decision_exit_code(decision: str, prune_ids: list[str], prune: dict[str, Any]) -> int:
    if decision == "error":
        return 2
    if decision not in DECISION_MESSAGES:
        return 1
    return 1 if prune_ids and not prune["performed"] else 0


def _check_decision(
    results: list[CheckResult],
    obligations: list[dict[str, Any]],
    partial: bool,
) -> tuple[str, str | None]:
    for result in results:
        if result.configuration_error:
            return "error", result.reason
    return gate_result.decision(results, obligations, partial=partial), None


def _finalize_check(
    root: Path, config: Config, results: list[CheckResult],
    prune_ids: list[str], selected: list[str] | None = None,
    affected_base: str | None = None,
) -> tuple[int, dict[str, Any]]:
    partial = selected is not None or affected_base is not None
    _assign_causes(config, results)
    obligations = gate_result.obligations(config, results, partial=partial)
    prune_document = _perform_prune(config, prune_ids, results)
    decision, configuration_error = _check_decision(results, obligations, partial)
    exit_code = _decision_exit_code(decision, prune_ids, prune_document)
    document = _result_document(
        root, config, decision, results, obligations, prune_document, selected,
    )
    if configuration_error is not None:
        document["error"] = configuration_error
    if affected_base is not None:
        document.update(scope="affected", base=affected_base)
    return exit_code, document


def _reject_unknown_checks(config: Config, identifiers: list[str]) -> None:
    known = list(config.checks)
    if config.module_contracts:
        known.insert(0, MODULE_CONTRACTS_ID)
    for identifier in identifiers:
        if identifier not in known:
            raise UsageError(
                f"qg.py check: unknown check {identifier!r}; known checks: {', '.join(known) or 'none'}"
            )


def _selected_check_ids(config: Config, only_ids: list[str] | None) -> list[str] | None:
    if only_ids is None:
        return None
    _require_distinct("check", only_ids)
    _reject_unknown_checks(config, only_ids)
    selected = _needed_order(config, [config.checks[name] for name in only_ids if name in config.checks])
    if MODULE_CONTRACTS_ID in only_ids:
        selected.insert(0, MODULE_CONTRACTS_ID)
    return selected


def _builtin_selection(files: list[str], inventory_code: int) -> dict[str, Any]:
    selected = dict.fromkeys(files, "full run") if inventory_code == 0 else {}
    return CheckSelection(selected, {}, "full run").report()


def _run_builtins(
    root: Path, config: Config, affected: bool, results: list[CheckResult], ledger: LedgerRun | None,
) -> tuple[list[str], dict[str, str], int]:
    with _dispatch_attempt(ledger, "inventory"):
        inventory, files, classes, code = _inventory_check(root, config)
        results.append(inventory)
    if affected:
        inventory.report_fields["selection"] = _builtin_selection(files, code)
    with _dispatch_attempt(ledger, "hygiene"):
        hygiene = _hygiene_check(root, config)
        results.append(hygiene)
    if affected:
        hygiene.report_fields["selection"] = inventory.report_fields["selection"]
    return files, classes, code


def _check_command(
    root: Path, config: Config, prune_ids: list[str], selected: list[str] | None,
    affected_base: str | None, diff: DiffBaseOverride | None,
    results: list[CheckResult], ledger: LedgerRun | None,
) -> tuple[int, dict[str, Any]]:
    files, classes, code = _run_builtins(root, config, diff is not None, results, ledger)
    configured = None if selected is None else [name for name in selected if name in config.checks]
    _run_policy_checks(
        root, config, files, classes, code, configured, base_override=diff,
        module_contracts=config.module_contracts, results=results, ledger=ledger,
    )
    exit_code, document = _finalize_check(root, config, results, prune_ids, selected, affected_base)
    if diff is not None:
        assert diff.changed_paths is not None
        document["changed_paths"] = sorted(diff.changed_paths)
    return exit_code, document


@contextlib.contextmanager
def _check_trust(trust: Any):
    if trust is None:
        yield
        return
    try:
        yield
    except BaseException as error:
        try:
            trust.close()
        except Exception as cleanup_error:
            error.add_note(str(cleanup_error))
        raise
    else:
        trust.close()


def _check_output(json_output: bool):
    return contextlib.redirect_stdout(sys.stderr) if json_output else contextlib.nullcontext()


def _run_check_engine(
    root: Path, config: Config, requested: list[str], only_ids: list[str] | None,
    affected_base: str | None, json_output: bool, trust: Any,
    ledger: LedgerRun | None, results: list[CheckResult],
) -> tuple[int, dict[str, Any]]:
    problem = _prune_request_problem(config, requested)
    if problem is not None:
        return _prune_option_error(root, config, requested, problem)
    selected = _selected_check_ids(config, only_ids)
    diff = affected_diff(root, affected_base) if affected_base is not None else None
    if ledger is not None:
        if diff is not None:
            ledger.diff = diff
        _begin_ledger(ledger, root, selected, affected_base)
    scope = trust.activate() if trust is not None else contextlib.nullcontext()
    with scope, _check_output(json_output):
        return _check_command(root, config, requested, selected, affected_base, diff, results, ledger)


def _append_check_evidence(
    root: Path, config: Config, ledger: LedgerRun | None, results: list[CheckResult],
    document: dict[str, Any], status: int | None, termination: str | None = None,
) -> None:
    if ledger is None or ledger.run_id is None:
        return
    version = document["gate_version"] if "gate_version" in document else gate_result.gate_version()
    record = gate_result.ledger_record(
        run_id=ledger.run_id, start=ledger.start, end=gate_result.consumer_identity(root, strict=True),
        version=version, digest=config.policy_sha256, selected=ledger.selected, base=ledger.affected_base,
        diff=ledger.diff, results=results, interrupted=ledger.interrupted, document=document,
        status=status, termination=termination,
    )
    gate_result.append_ledger(ledger.destination, ledger.supplied, record)


def _append_during_unwind(
    root: Path, config: Config, ledger: LedgerRun | None, results: list[CheckResult],
    document: dict[str, Any], error: BaseException,
) -> None:
    if ledger is None:
        return
    status = error.exit_code if isinstance(error, GateError) else None
    try:
        _append_check_evidence(root, config, ledger, results, document, status, type(error).__name__)
    except Exception as append_error:
        error.add_note(str(append_error))


def _publish_check(
    document: dict[str, Any], results: list[CheckResult], notices: list[str], json_output: bool,
) -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    if json_output:
        print(json.dumps(document, indent=2, allow_nan=False), flush=True)
    if results:
        with _check_output(json_output):
            _print_check_report(document, results, notices)


def command_check(
    root: Path,
    config: Config,
    *,
    json_output: bool = False,
    prune_ids: list[str] | None = None,
    only_ids: list[str] | None = None,
    trust: Any = None,
    affected_base: str | None = None,
    ledger_path: str | None = None,
) -> int:
    ledger = LedgerRun(Path.cwd() / ledger_path, ledger_path) if ledger_path is not None else None
    results: list[CheckResult] = []
    notices: list[str] = []
    document: dict[str, Any] = {}
    try:
        with _check_trust(trust):
            code, document = _run_check_engine(
                root, config, prune_ids or [], only_ids, affected_base, json_output, trust, ledger, results,
            )
            if trust is not None:
                code, document = trust.finish(code, document, notices=notices)
    except BaseException as error:
        _append_during_unwind(root, config, ledger, results, document, error)
        raise
    _append_check_evidence(root, config, ledger, results, document, code)
    _publish_check(document, results, notices, json_output)
    return code
