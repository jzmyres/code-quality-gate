"""Check adapters, the check runner and the combined check command."""
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import gate_result
from .clones import measure_clones
from .coverage_tool import combine_coverage
from .files import command_hygiene, validate_inventory
from .policy import (
    CheckDef,
    Config,
    GateError,
    UnsupportedError,
    UsageError,
)
from .python_crap import measure_crap
from .python_tests import coverage_prefix, expand_run, parse_test_count
from .ratchet import (
    RatchetResult,
    evaluate,
    load_baseline,
    pruned_entries,
    write_baseline,
)
from .tools import load_tools, tool_binary, _default_lock_path


CLONE_BUDGET_SECONDS = 600


@dataclass
class CheckResult:
    id: str
    tier: int
    enforcement: str
    adapter: str
    metric_version: str
    outcome: str
    duration_seconds: float
    budget_seconds: int
    termination: str
    findings: list[Any] = field(default_factory=list)
    resolved_baseline_entries: list[str] = field(default_factory=list)
    threshold: float | None = None
    baseline_path: Path | None = None
    ratchet: RatchetResult | None = None
    measurement: dict[str, Any] | None = None
    evidence: Path | None = None
    temporary: Any = field(default=None, repr=False, compare=False)

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "id": self.id,
            "tier": self.tier,
            "enforcement": self.enforcement,
            "adapter": self.adapter,
            "metric_version": self.metric_version,
            "outcome": self.outcome,
            "duration_seconds": round(self.duration_seconds, 6),
            "budget_seconds": self.budget_seconds,
            "termination": self.termination,
            "findings": [
                item.to_json() if hasattr(item, "to_json") else item
                for item in self.findings
            ],
            "resolved_baseline_entries": list(self.resolved_baseline_entries),
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


def _combine(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    def text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return value

    first = text(stdout)
    second = text(stderr)
    if first and second and not first.endswith("\n"):
        first += "\n"
    return first + second


def _expand_run(
    check: CheckDef, files: list[str]
) -> tuple[list[str], str | None]:
    assert check.command is not None
    expanded: list[str] = []
    tools = None
    lock = _default_lock_path()
    for argument in check.command.run:
        if argument == "{files}":
            expanded.extend(files)
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


def _command_result(
    check: CheckDef,
    start: float,
    *,
    outcome: str,
    termination: str = "exit",
) -> CheckResult:
    duration = time.monotonic() - start
    assert check.command is not None
    return CheckResult(
        id=check.id,
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        metric_version=check.metric_version,
        outcome=outcome,
        duration_seconds=duration,
        budget_seconds=check.command.budget_seconds,
        termination=termination,
        threshold=check.threshold,
        baseline_path=check.baseline,
    )


def _adapter_result(
    check: CheckDef,
    start: float,
    outcome: str,
    *,
    budget_seconds: int,
    termination: str = "exit",
    **fields: Any,
) -> CheckResult:
    return CheckResult(
        id=check.id,
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        metric_version=check.metric_version,
        outcome=outcome,
        duration_seconds=time.monotonic() - start,
        budget_seconds=budget_seconds,
        termination=termination,
        **fields,
    )


def _run_command(
    root: Path,
    config: Config,
    check: CheckDef,
    files: list[str],
    classes: dict[str, str],
    prefix: str,
) -> CheckResult:
    assert check.command is not None
    start = time.monotonic()
    selected, names = _select_files(config, check, files, classes)
    if "{files}" in check.command.run and not selected:
        class_text = ", ".join(names) or "none"
        print(
            f"{prefix}: no files selected (classes: {class_text}); "
            "zero inputs is not a pass",
            file=sys.stderr,
        )
        return _command_result(check, start, outcome="fail")
    try:
        expanded, unsupported = _expand_run(check, selected)
    except UsageError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _command_result(check, start, outcome="error")
    if unsupported is not None:
        print(f"{prefix}: {unsupported}", file=sys.stderr)
        return _command_result(check, start, outcome="unsupported")
    try:
        completed = subprocess.run(
            expanded,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=check.command.budget_seconds,
        )
    except subprocess.TimeoutExpired as error:
        combined = _combine(error.stdout, error.stderr)
        print(
            f"{prefix}: command exceeded its "
            f"{check.command.budget_seconds} second budget",
            file=sys.stderr,
        )
        if combined.strip():
            print(combined.rstrip(), file=sys.stderr)
        return _command_result(check, start, outcome="fail", termination="budget")
    except OSError as error:
        print(f"{prefix}: cannot run command: {error}", file=sys.stderr)
        return _command_result(check, start, outcome="error")

    combined = _combine(completed.stdout, completed.stderr)
    termination = "signal" if completed.returncode < 0 else "exit"
    if completed.returncode < 0:
        print(
            f"{prefix}: command terminated by signal {-completed.returncode}",
            file=sys.stderr,
        )
        if combined.strip():
            print(combined.rstrip(), file=sys.stderr)
        return _command_result(check, start, outcome="fail", termination=termination)
    if completed.returncode != 0:
        print(
            f"{prefix}: command exited {completed.returncode}",
            file=sys.stderr,
        )
        if combined.strip():
            print(combined.rstrip(), file=sys.stderr)
        return _command_result(check, start, outcome="fail")
    if (
        check.command.must_match_pattern is not None
        and check.command.must_match_pattern.search(combined) is None
    ):
        print(
            f"{prefix}: output did not match must_match "
            f"{check.command.must_match!r}",
            file=sys.stderr,
        )
        if combined.strip():
            print(combined.rstrip(), file=sys.stderr)
        return _command_result(check, start, outcome="fail")

    result = _command_result(check, start, outcome="pass")
    print(
        f"{prefix}: passed (exit 0, {result.duration_seconds:.2f}s)",
        flush=True,
    )
    return result


def _clone_result(
    check: CheckDef,
    start: float,
    *,
    outcome: str,
    termination: str = "exit",
    ratchet: RatchetResult | None = None,
) -> CheckResult:
    assert check.clones is not None
    return CheckResult(
        id=check.id,
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        metric_version=check.metric_version,
        outcome=outcome,
        duration_seconds=time.monotonic() - start,
        budget_seconds=CLONE_BUDGET_SECONDS,
        termination=termination,
        findings=ratchet.findings if ratchet is not None else [],
        resolved_baseline_entries=ratchet.resolved if ratchet is not None else [],
        threshold=check.threshold,
        baseline_path=check.baseline,
        ratchet=ratchet,
    )


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
        class_text = ", ".join(names) or "none"
        print(
            f"{prefix}: no files selected (classes: {class_text}); "
            "zero inputs is not a pass",
            file=sys.stderr,
        )
        return _clone_result(check, start, outcome="fail")
    try:
        findings = measure_clones(root, selected, check.clones.min_tokens)
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _clone_result(check, start, outcome="unsupported")
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _clone_result(check, start, outcome="error")
    try:
        entries = load_baseline(check.baseline, allowed_extras=("files",))
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _clone_result(check, start, outcome="error")
    assert check.threshold is not None
    ratchet = evaluate(
        findings,
        entries,
        threshold=check.threshold,
        enforcement=check.enforcement,
        prefix=prefix,
        adapter=check.adapter,
    )
    result = _clone_result(
        check, start, outcome=ratchet.outcome, ratchet=ratchet
    )
    if ratchet.outcome == "pass":
        if findings:
            noun = "clone" if len(findings) == 1 else "clones"
            print(
                f"{prefix}: {len(findings)} {noun} within baseline",
                flush=True,
            )
        else:
            print(f"{prefix}: 0 clones", flush=True)
    return result


def _print_output(prefix: str, combined: str) -> None:
    if combined.strip():
        print(combined.rstrip(), file=sys.stderr)


def _run_python_tests(
    root: Path,
    check: CheckDef,
    *,
    prefix: str,
) -> CheckResult:
    assert check.python_tests is not None
    spec = check.python_tests
    start = time.monotonic()

    def result(
        outcome: str,
        *,
        termination: str = "exit",
        **fields: Any,
    ) -> CheckResult:
        return _adapter_result(
            check,
            start,
            outcome,
            budget_seconds=spec.budget_seconds,
            termination=termination,
            **fields,
        )

    temporary = tempfile.TemporaryDirectory(prefix="qg-coverage-")
    data_dir = Path(temporary.name) / "data"
    try:
        data_dir.mkdir()
        python_prefix = coverage_prefix(root, data_dir)
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("unsupported")
    except OSError as error:
        print(f"{prefix}: cannot create coverage data directory: {error}", file=sys.stderr)
        return result("error")

    command = expand_run(spec.run, python_prefix)
    environment = os.environ.copy()
    environment["QG_PYTHON"] = json.dumps(python_prefix)
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=spec.budget_seconds,
        )
    except subprocess.TimeoutExpired as error:
        combined = _combine(error.stdout, error.stderr)
        print(
            f"{prefix}: command exceeded its {spec.budget_seconds} second budget",
            file=sys.stderr,
        )
        _print_output(prefix, combined)
        return result("fail", termination="budget")
    except OSError as error:
        print(f"{prefix}: cannot run command: {error}", file=sys.stderr)
        return result("error")

    combined = _combine(completed.stdout, completed.stderr)
    if completed.returncode < 0:
        print(
            f"{prefix}: command terminated by signal {-completed.returncode}",
            file=sys.stderr,
        )
        _print_output(prefix, combined)
        return result("fail", termination="signal")
    if completed.returncode != 0:
        count, _count_error = parse_test_count(spec, combined)
        if count == 0:
            print(
                f"{prefix}: command exited {completed.returncode} and "
                "reported 0 tests; zero tests is not a pass",
                file=sys.stderr,
            )
        else:
            print(
                f"{prefix}: command exited {completed.returncode}",
                file=sys.stderr,
            )
        _print_output(prefix, combined)
        return result("fail")

    count, count_error = parse_test_count(spec, combined)
    if count_error is not None:
        print(f"{prefix}: {count_error}", file=sys.stderr)
        _print_output(prefix, combined)
        return result("unsupported")
    assert count is not None
    if count == 0:
        print(
            f"{prefix}: command reported 0 tests; zero tests is not a pass",
            file=sys.stderr,
        )
        _print_output(prefix, combined)
        return result("fail")

    combined_file = Path(temporary.name) / "combined" / ".coverage"
    try:
        combine_coverage(data_dir, combined_file)
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("unsupported")
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("unsupported")

    outcome = result(
        "pass",
        measurement={"tests": count},
        evidence=combined_file,
        temporary=temporary,
    )
    print(
        f"{prefix}: passed ({count} tests, "
        f"{outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


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

    def result(
        outcome: str,
        *,
        ratchet: RatchetResult | None = None,
        measurement: dict[str, Any] | None = None,
    ) -> CheckResult:
        return _adapter_result(
            check,
            start,
            outcome,
            budget_seconds=CLONE_BUDGET_SECONDS,
            findings=ratchet.findings if ratchet is not None else [],
            resolved_baseline_entries=(
                ratchet.resolved if ratchet is not None else []
            ),
            threshold=check.threshold,
            baseline_path=check.baseline,
            ratchet=ratchet,
            measurement=measurement,
        )

    selected, names = _select_files(config, check, files, classes)
    if not selected:
        class_text = ", ".join(names) or "none"
        print(
            f"{prefix}: no files selected (classes: {class_text}); "
            "zero inputs is not a pass",
            file=sys.stderr,
        )
        return result("fail")

    required = prior.get(spec.requires)
    if required is None or required.outcome != "pass":
        print(
            f"{prefix}: coverage unreliable: {spec.requires} did not pass",
            file=sys.stderr,
        )
        return result("unsupported")
    if required.evidence is None or not required.evidence.is_file():
        print(
            f"{prefix}: coverage unreliable: {spec.requires} produced no "
            "combined coverage data",
            file=sys.stderr,
        )
        return result("unsupported")

    try:
        measurement = measure_crap(root, selected, required.evidence)
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("unsupported")
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("error")
    if measurement.failures:
        for failure in measurement.failures:
            print(f"{prefix}: {failure}", file=sys.stderr)
        return result("fail")

    try:
        entries = load_baseline(check.baseline)
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return result("error")
    assert check.threshold is not None
    ratchet = evaluate(
        measurement.findings,
        entries,
        threshold=check.threshold,
        enforcement=check.enforcement,
        prefix=prefix,
        adapter=check.adapter,
    )
    outcome = result(
        ratchet.outcome,
        ratchet=ratchet,
        measurement={"functions": len(measurement.findings)},
    )
    if ratchet.outcome == "pass":
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
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        metric_version=check.metric_version,
        outcome="unsupported",
        duration_seconds=0.0,
        budget_seconds=budget,
        termination="exit",
        threshold=check.threshold,
        baseline_path=check.baseline,
    )


def _run_inventory(
    root: Path, config: Config
) -> tuple[int, list[str], dict[str, str]]:
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        print(f"inventory: {error}", file=sys.stderr)
        return 1, [], {}
    if violations:
        for violation in violations:
            print(f"inventory: {violation}", file=sys.stderr)
        return 1, [], {}
    print(f"inventory: {len(files)} files match {len(config.rules)} rules")
    return 0, files, classes


def _check_command(
    root: Path, config: Config, prune_id: str | None
) -> tuple[int, dict[str, Any]]:
    if prune_id is not None:
        if prune_id not in config.checks:
            message = (
                f"check: unknown check {prune_id!r}; known checks: "
                f"{', '.join(config.checks) or 'none'}"
            )
            print(message, file=sys.stderr)
            return 2, gate_result.error_document(
                root, config.path, message
            )
        if config.checks[prune_id].baseline is None:
            message = f"check: {prune_id}: no baseline to prune"
            print(message, file=sys.stderr)
            return 2, gate_result.error_document(
                root, config.path, message
            )

    print("check: inventory", flush=True)
    inventory_code, files, classes = _run_inventory(root, config)
    print("check: hygiene", flush=True)
    hygiene_code = command_hygiene(root, config)

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

    prune_refused = False
    if prune_id is not None:
        target = next(item for item in results if item.id == prune_id)
        check = config.checks[prune_id]
        if target.outcome != "pass" or target.ratchet is None:
            print(
                f"check: {prune_id}: prune refused because the check did not "
                "pass; nothing written",
                file=sys.stderr,
            )
            prune_refused = True
        else:
            assert check.baseline is not None
            existed = check.baseline.exists()
            try:
                write_baseline(check.baseline, pruned_entries(target.ratchet))
            except GateError as error:
                print(f"check: {prune_id}: {error}", file=sys.stderr)
                prune_refused = True
            else:
                if check.baseline.exists():
                    print(f"check: {prune_id}: baseline updated at {check.baseline}")
                elif existed:
                    print(f"check: {prune_id}: baseline removed at {check.baseline}")

    decision = gate_result.decision(inventory_code, hygiene_code, results)
    if decision == "rejected":
        failed = []
        if inventory_code != 0:
            failed.append("inventory")
        if hygiene_code != 0:
            failed.append("hygiene")
        failed.extend(
            result.id
            for result in results
            if result.enforcement == "enforced" and result.outcome != "pass"
        )
        print(f"check: failed ({', '.join(failed)})", file=sys.stderr)
    elif decision == "accepted_with_exceptions":
        print(
            f"check: passed with exceptions ({2 + len(results)} checks)",
            flush=True,
        )
    else:
        print(f"check: passed ({2 + len(results)} checks)", flush=True)

    exit_code = 0 if decision in ("accepted", "accepted_with_exceptions") else 1
    if prune_refused:
        exit_code = 1
    document = {
        "schema": 1,
        "gate_version": gate_result.gate_version(),
        "revision": gate_result.consumer_revision(root),
        "dirty": gate_result.consumer_dirty(root),
        "policy_sha256": gate_result.policy_sha256(config.path),
        "decision": decision,
        "checks": [result.to_json() for result in results],
    }
    return exit_code, document


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
    print(json.dumps(document, indent=2), file=sys.stdout)
    return code
