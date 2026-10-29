"""The churn x current-value worklist for reasoned baseline entries."""
from __future__ import annotations

import contextlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .checks import CheckResult, _inventory_check, run_check
from .files import git_argv
from .policy import CheckDef, Config, GateError, UsageError
from .ratchet import BaselineEntry, FindingResult
from .runner import run


GIT_BUDGET_SECONDS = 60.0


@dataclass(frozen=True)
class Row:
    check: str
    subject: str
    churn: int
    bound: float
    value: float
    location: str

    @property
    def product(self) -> float:
        return self.churn * self.value

    def to_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "subject": self.subject,
            "churn": self.churn,
            "bound": self.bound,
            "value": self.value,
            "churn_x_value": self.product,
            "location": self.location,
        }


@dataclass(frozen=True)
class Note:
    check: str
    subject: str
    reason: str
    file: str | None = None

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "check": self.check,
            "subject": self.subject,
            "reason": self.reason,
        }
        if self.file is not None:
            document["file"] = self.file
        return document


def _qualifies(check: CheckDef) -> bool:
    return (
        check.baseline is not None
        and check.direction == "max"
        and check.threshold is not None
    )


def _max_problem(check: CheckDef) -> str | None:
    if check.direction != "max":
        return f"expected a max metric, got {check.direction!r}"
    if check.threshold is None:
        return "expected a max metric with a threshold, got none"
    return None


def _requested_check(config: Config, identifier: str) -> CheckDef:
    check = config.checks.get(identifier)
    if check is None:
        known = ", ".join(config.checks) or "none"
        raise UsageError(
            f"qg.py worklist: unknown check {identifier!r}; known checks: {known}"
        )
    if check.baseline is None:
        raise UsageError(
            f"qg.py worklist: check {identifier!r}: expected a baseline, got none"
        )
    problem = _max_problem(check)
    if problem is not None:
        raise UsageError(f"qg.py worklist: check {identifier!r}: {problem}")
    return check


def _select_checks(config: Config, identifiers: list[str]) -> list[CheckDef]:
    if identifiers:
        return [
            _requested_check(config, identifier) for identifier in identifiers
        ]
    return [check for check in config.checks.values() if _qualifies(check)]


def _required(config: Config, check: CheckDef) -> list[str]:
    identifiers: list[str] = []
    required = getattr(check.spec, "requires", None)
    while required is not None and required not in identifiers:
        identifiers.append(required)
        required = getattr(config.checks[required].spec, "requires", None)
    return identifiers


def _needed_order(config: Config, selected: list[CheckDef]) -> list[str]:
    needed = {check.id for check in selected}
    for check in selected:
        needed.update(_required(config, check))
    return [
        check.id for check in config.checks.values() if check.id in needed
    ]


def _run_selected(
    root: Path, config: Config, selected: list[CheckDef]
) -> tuple[CheckResult, dict[str, CheckResult], list[str]]:
    order = _needed_order(config, selected)
    inventory, files, classes, code = _inventory_check(root, config)
    if code != 0:
        return inventory, {}, order
    results: dict[str, CheckResult] = {}
    for check in config.checks.values():
        if check.id not in order:
            continue
        print(f"check: {check.id} ({check.adapter})", flush=True)
        results[check.id] = run_check(
            root,
            config,
            check,
            files,
            classes,
            prefix=f"check: {check.id}",
            prior=results,
        )
    return inventory, results, order


def _passes(result: CheckResult) -> bool:
    if result.satisfied is not None:
        return bool(result.satisfied)
    return result.outcome == "pass"


def _failure_message(result: CheckResult) -> str:
    reason = f": {result.reason}" if result.reason else ""
    return (
        f"worklist: {result.id}: expected a passing check, "
        f"got {result.outcome}{reason}"
    )


def _first_failure(
    results: dict[str, CheckResult], order: list[str]
) -> CheckResult | None:
    for identifier in order:
        if not _passes(results[identifier]):
            return results[identifier]
    return None


def _location_file(location: str) -> str:
    first = location.split(";", 1)[0].strip()
    path, separator, _line = first.rpartition(":")
    return path if separator else first


def _finding_file(finding: FindingResult) -> str:
    if finding.locations:
        return finding.locations[0].path
    return _location_file(finding.location)


def _git_churn(root: Path, file: str) -> int | None:
    argv = git_argv(root, "log", "--follow", "--format=%H", "--", file)
    result = run(argv, cwd=str(root), budget_seconds=GIT_BUDGET_SECONDS)
    command = f"git log --follow --format=%H -- {file}"
    if result.execution != "completed" or result.returncode != 0:
        actual = result.error if result.execution == "error" else str(
            result.returncode
        )
        detail = result.stderr_text.strip()
        message = f"{command}: expected exit status 0, got {actual}"
        raise GateError(f"{message}: {detail}" if detail else message)
    commits = result.stdout_text.splitlines()
    return len(commits) or None


def _churn(root: Path, file: str, cache: dict[str, int | None]) -> int | None:
    if file not in cache:
        cache[file] = _git_churn(root, file)
    return cache[file]


def _debt_entries(
    entries: list[BaselineEntry], threshold: float
) -> list[BaselineEntry]:
    return [
        entry
        for entry in entries
        if entry.direction == "max" and entry.bound > threshold
    ]


def _findings_by_subject(
    findings: list[FindingResult],
) -> dict[str, FindingResult]:
    return {finding.subject: finding for finding in findings}


def _entry_row(
    root: Path,
    check_id: str,
    entry: BaselineEntry,
    finding: FindingResult | None,
    churn: dict[str, int | None],
) -> tuple[Row | None, Note | None]:
    if finding is None:
        return None, Note(check_id, entry.subject, "no longer exists")
    file = _finding_file(finding)
    count = _churn(root, file, churn)
    if count is None:
        return None, Note(check_id, entry.subject, "churn not measured", file)
    return (
        Row(
            check_id,
            entry.subject,
            count,
            entry.bound,
            finding.value,
            finding.location,
        ),
        None,
    )


def _check_debt(
    root: Path,
    check: CheckDef,
    result: CheckResult,
    churn: dict[str, int | None],
) -> tuple[list[Row], list[Note]]:
    ratchet = result.ratchet
    if ratchet is None:
        return [], []
    assert check.threshold is not None
    entries = _debt_entries(ratchet.entries, check.threshold)
    findings = _findings_by_subject(ratchet.findings)
    rows: list[Row] = []
    notes: list[Note] = []
    for entry in entries:
        row, note = _entry_row(
            root, check.id, entry, findings.get(entry.subject), churn
        )
        if row is not None:
            rows.append(row)
        if note is not None:
            notes.append(note)
    return rows, notes


def _collect(
    root: Path,
    selected: list[CheckDef],
    results: dict[str, CheckResult],
) -> tuple[list[Row], list[Note]]:
    rows: list[Row] = []
    notes: list[Note] = []
    churn: dict[str, int | None] = {}
    for check in selected:
        check_rows, check_notes = _check_debt(
            root, check, results[check.id], churn
        )
        rows.extend(check_rows)
        notes.extend(check_notes)
    return rows, notes


def _worklist_report(
    root: Path, config: Config, check_ids: list[str]
) -> tuple[int, list[Row], list[Note]]:
    selected = _select_checks(config, check_ids)
    if not selected:
        return 0, [], []
    inventory, results, order = _run_selected(root, config, selected)
    if not _passes(inventory):
        print(_failure_message(inventory), file=sys.stderr)
        return 1, [], []
    failure = _first_failure(results, order)
    if failure is not None:
        print(_failure_message(failure), file=sys.stderr)
        return 1, [], []
    try:
        rows, notes = _collect(root, selected, results)
    except GateError as error:
        print(f"worklist: {error}", file=sys.stderr)
        return 1, [], []
    rows.sort(key=lambda row: row.product, reverse=True)
    return 0, rows, notes


def _note_text(note: Note) -> str:
    if note.file is None:
        return note.reason
    return f"{note.reason} ({note.file})"


def _print_report(rows: list[Row], notes: list[Note]) -> None:
    print("worklist: churn x current value")
    print(
        f"{'CHURN':>5} {'BOUND':>7} {'VALUE':>7} {'CHURNxVALUE':>12}  "
        "CHECK  SUBJECT  LOCATION"
    )
    for row in rows:
        print(
            f"{row.churn:>5} {row.bound:>7.1f} {row.value:>7.1f} "
            f"{row.product:>12.1f}  {row.check}  {row.subject}  "
            f"{row.location}"
        )
    if notes:
        print("")
        print("Not ranked:")
        for note in notes:
            print(f"  {note.check}: {note.subject}: {_note_text(note)}")


def _document(rows: list[Row], notes: list[Note]) -> dict[str, Any]:
    return {
        "schema": 1,
        "rows": [row.to_json() for row in rows],
        "notes": [note.to_json() for note in notes],
    }


def command_worklist(
    root: Path, config: Config, check_ids: list[str], json_output: bool
) -> int:
    if json_output:
        with contextlib.redirect_stdout(sys.stderr):
            code, rows, notes = _worklist_report(root, config, check_ids)
        if code == 0:
            print(
                json.dumps(_document(rows, notes), indent=2, allow_nan=False)
            )
        return code
    code, rows, notes = _worklist_report(root, config, check_ids)
    if code == 0:
        _print_report(rows, notes)
    return code
