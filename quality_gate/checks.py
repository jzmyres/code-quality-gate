"""Shared check machinery, the check runner and the combined check command."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import gate_result
from .adapters import AdapterContext, adapter_for
from .files import (
    DiffBaseOverride,
    git_argv,
    hygiene_result,
    resolve_diff_base,
    validate_inventory,
)
from .policy import (
    CheckDef,
    Config,
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
    Diagnostics,
    RunTimeout,
    check_deadline,
    mark_step,
)


RATCHET_BUDGET_SECONDS = 600
# In-process analysis over bounded input takes seconds, so this allowance keeps
# the run's wall-clock backstop from racing a subprocess budget, which must end
# its check and never the run.  The timer starts before every subprocess, so a
# run limit of exactly the budgets would always win over a hanging last check.
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
    evidence_dir: Path,
    prior: dict[str, CheckResult],
    base_override: DiffBaseOverride | None = None,
) -> CheckResult:
    context = AdapterContext(
        root, config, check, files, classes, prefix, prior, evidence_dir,
        base_override,
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
) -> CheckResult:
    _check_descriptor(check)
    start = time.monotonic()
    with check_deadline(check.id, start, _check_budget(check)):
        return _adapter_runner(
            root, config, check, files, classes, prefix, evidence_dir,
            prior or {}, base_override,
        )


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


def _run_limit(selected_checks: Iterable[CheckDef]) -> float:
    return (
        sum(_check_budget(check) for check in selected_checks)
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


def _run_policy_checks(
    root: Path,
    config: Config,
    files: list[str],
    classes: dict[str, str],
    inventory_code: int,
    selected_ids: list[str] | None = None,
) -> list[CheckResult]:
    selected = list(config.checks) if selected_ids is None else selected_ids
    selected_checks = [config.checks[identifier] for identifier in selected]
    results: list[CheckResult] = []
    prior: dict[str, CheckResult] = {}
    run_directory = tempfile.TemporaryDirectory(prefix="qg-run-")
    previous = _arm_run_limit(_run_limit(selected_checks))
    try:
        base_override = resolve_diff_base(root)
        try:
            for check in selected_checks:
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
                evidence_dir = Path(run_directory.name) / check.id
                evidence_dir.mkdir()
                outcome = run_check(
                    root,
                    config,
                    check,
                    files,
                    classes,
                    prefix=f"check: {check.id}",
                    evidence_dir=evidence_dir,
                    prior=prior,
                    base_override=base_override,
                )
                results.append(outcome)
                prior[check.id] = outcome
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
    """The rejection summary, then a consequences line when there is one."""
    entries = _failure_entries(results, obligations)
    roots: list[str] = []
    consequences: list[str] = []
    for name, caused_by in entries:
        if caused_by is None:
            roots.append(name)
        else:
            consequences.append(f"{name} because {', '.join(caused_by)}")
    lines = [f"check: failed ({', '.join(roots)})"]
    if consequences:
        lines.append(f"check: consequences ({'; '.join(consequences)})")
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
    trust: Any = None,
    selected: list[str] | None = None,
) -> dict[str, Any]:
    document = {
        "schema": 3,
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
            *_rejection_lines(results, obligations),
            sep="\n",
            file=sys.stderr,
        )
    elif decision == "accepted_with_exceptions":
        print(
            f"check: passed with exceptions ({len(results)} checks)",
            flush=True,
        )
    elif decision == "partial":
        print(f"check: partial run passed ({len(results)} checks)", flush=True)
    else:
        print(f"check: passed ({len(results)} checks)", flush=True)



def _decision_exit_code(decision: str, prune_ids: list[str], prune: dict[str, Any]) -> int:
    if decision == "error":
        return 2
    if decision not in ("accepted", "accepted_with_exceptions", "partial"):
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
    prune_ids: list[str], trust: Any, selected: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    partial = selected is not None
    _assign_causes(config, results)
    obligations = [] if partial else gate_result.obligations(config, results)
    prune_document = _perform_prune(config, prune_ids, results)
    decision, configuration_error = _check_decision(results, obligations, partial)
    _print_decision(decision, configuration_error, results, obligations)
    exit_code = _decision_exit_code(decision, prune_ids, prune_document)
    document = _result_document(
        root, config, decision, results, obligations, prune_document, trust,
        selected,
    )
    if configuration_error is not None:
        document["error"] = configuration_error
    return exit_code, document


def _reject_unknown_checks(config: Config, identifiers: list[str]) -> None:
    known = ", ".join(config.checks) or "none"
    for identifier in identifiers:
        if identifier not in config.checks:
            raise UsageError(
                f"qg.py check: unknown check {identifier!r}; known checks: {known}"
            )


def _selected_check_ids(config: Config, only_ids: list[str] | None) -> list[str] | None:
    if only_ids is None:
        return None
    _require_distinct("check", only_ids)
    _reject_unknown_checks(config, only_ids)
    return _needed_order(config, [config.checks[identifier] for identifier in only_ids])


def _check_command(
    root: Path,
    config: Config,
    prune_ids: list[str],
    trust: Any = None,
    only_ids: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    problem = _prune_request_problem(config, prune_ids)
    if problem is not None:
        return _prune_option_error(root, config, prune_ids, problem)
    selected = _selected_check_ids(config, only_ids)
    inventory, files, classes, code = _inventory_check(root, config)
    results = [inventory, _hygiene_check(root, config)]
    results.extend(
        _run_policy_checks(root, config, files, classes, code, selected)
    )
    return _finalize_check(root, config, results, prune_ids, trust, selected)


def _run_check_document(
    root: Path,
    config: Config,
    prune_ids: list[str],
    json_output: bool,
    trust: Any = None,
    only_ids: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    if not json_output:
        return _check_command(root, config, prune_ids, trust, only_ids)
    with contextlib.redirect_stdout(sys.stderr):
        return _check_command(root, config, prune_ids, trust, only_ids)


def command_check(
    root: Path,
    config: Config,
    *,
    json_output: bool = False,
    prune_ids: list[str] | None = None,
    only_ids: list[str] | None = None,
    trust: Any = None,
) -> int:
    requested = prune_ids or []
    if trust is None:
        code, document = _run_check_document(
            root, config, requested, json_output, only_ids=only_ids
        )
    else:
        try:
            with trust.activate():
                code, document = _run_check_document(
                    root, config, requested, json_output, trust, only_ids
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
