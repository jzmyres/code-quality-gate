"""The churn x current-value worklist for reasoned baseline entries."""
from __future__ import annotations

import contextlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .checks import (
    CheckResult,
    _inventory_check,
    _needed_order,
    _require_distinct,
    _run_policy_checks,
)
from .files import git_argv
from .policy import CheckDef, Config, GateError, UsageError
from .ratchet import BaselineEntry, FindingResult, RatchetResult
from .runner import RunResult, run


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


@dataclass(frozen=True)
class Slack:
    check: str
    subject: str
    bound: float
    value: float

    @property
    def amount(self) -> float:
        return self.value - self.bound

    def to_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "subject": self.subject,
            "bound": self.bound,
            "value": self.value,
            "slack": self.amount,
        }


def _qualifies(check: CheckDef) -> bool:
    return check.baseline is not None and check.threshold is not None


def _metric_problem(check: CheckDef) -> str | None:
    if check.threshold is None:
        return "expected a metric with a threshold, got none"
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
    problem = _metric_problem(check)
    if problem is not None:
        raise UsageError(f"qg.py worklist: check {identifier!r}: {problem}")
    return check


def _select_checks(config: Config, identifiers: list[str]) -> list[CheckDef]:
    _require_distinct("worklist", identifiers)
    if identifiers:
        return [
            _requested_check(config, identifier) for identifier in identifiers
        ]
    return [check for check in config.checks.values() if _qualifies(check)]


def _run_selected(
    root: Path, config: Config, selected: list[CheckDef]
) -> tuple[CheckResult, dict[str, CheckResult], list[str]]:
    order = _needed_order(config, selected)
    inventory, files, classes, code = _inventory_check(root, config)
    if code != 0:
        return inventory, {}, order
    results = _run_policy_checks(root, config, files, classes, code, order)
    return inventory, {result.id: result for result in results}, order


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


def _selected_failure(
    inventory: CheckResult, results: dict[str, CheckResult], order: list[str]
) -> CheckResult | None:
    if not _passes(inventory):
        return inventory
    return _first_failure(results, order)


def _location_file(location: str) -> str:
    first = location.split(";", 1)[0].strip()
    path, separator, _line = first.rpartition(":")
    return path if separator else first


def _finding_file(finding: FindingResult) -> str:
    if finding.locations:
        return finding.locations[0].path
    return _location_file(finding.location)


def _churn_failure(command: str, result: RunResult) -> GateError:
    actual = result.error if result.execution == "error" else str(result.returncode)
    detail = result.stderr_text.strip()
    message = f"{command}: expected exit status 0, got {actual}"
    return GateError(f"{message}: {detail}" if detail else message)


def _git_churn(root: Path, file: str) -> int | None:
    argv = git_argv(root, "--literal-pathspecs", "log", "--follow", "--format=%H", "--", file)
    result = run(argv, cwd=str(root), budget_seconds=GIT_BUDGET_SECONDS, capture_limit=None)
    command = f"git --literal-pathspecs log --follow --format=%H -- {file}"
    if result.execution != "completed" or result.returncode != 0:
        raise _churn_failure(command, result)
    if result.output_truncated:
        raise GateError(f"{command}: expected complete output, got truncated output")
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


def _missing_entry_note(check_id: str, entry: BaselineEntry, ratchet: RatchetResult) -> Note:
    if entry.subject in ratchet.unmeasured:
        return Note(check_id, entry.subject, "unmeasured")
    if entry.subject in ratchet.resolved:
        return Note(check_id, entry.subject, "no longer exists")
    raise GateError(f"{check_id}: {entry.subject}: missing ratchet classification")


def _entry_row(
    root: Path,
    check_id: str,
    entry: BaselineEntry,
    finding: FindingResult | None,
    ratchet: RatchetResult,
    churn: dict[str, int | None],
) -> tuple[Row | None, Note | None]:
    if entry.subject not in ratchet.measured:
        return None, _missing_entry_note(check_id, entry, ratchet)
    if finding is None:
        raise GateError(f"{check_id}: {entry.subject}: measured subject has no finding")
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
            root, check.id, entry, findings.get(entry.subject), ratchet, churn
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


def _slack_for_check(check: CheckDef, result: CheckResult) -> tuple[list[Slack], list[Note]]:
    ratchet = result.ratchet
    if ratchet is None:
        return [], []
    return _slack_for_entries(check.id, ratchet)


def _slack_for_entries(check_id: str, ratchet: Any) -> tuple[list[Slack], list[Note]]:
    slack: list[Slack] = []
    notes: list[Note] = []
    for entry in _minimum_entries(ratchet.entries):
        item, note = _slack_entry(check_id, entry, ratchet)
        if item is not None:
            slack.append(item)
        if note is not None:
            notes.append(note)
    return slack, notes


def _minimum_entries(entries: list[BaselineEntry]) -> list[BaselineEntry]:
    return [entry for entry in entries if entry.direction == "min"]


def _slack_entry(check_id: str, entry: BaselineEntry, ratchet: Any) -> tuple[Slack | None, Note | None]:
    value = ratchet.measured.get(entry.subject)
    if value is None:
        if entry.subject in ratchet.resolved:
            return None, Note(check_id, entry.subject, "no longer exists")
        if entry.subject in ratchet.unmeasured:
            return None, Note(check_id, entry.subject, "not measured")
        raise GateError(f"{check_id}: {entry.subject}: missing ratchet classification")
    return Slack(check_id, entry.subject, entry.bound, value), None


def _collect_slack(
    selected: list[CheckDef], results: dict[str, CheckResult]
) -> tuple[list[Slack], list[Note]]:
    slack: list[Slack] = []
    notes: list[Note] = []
    for check in selected:
        check_slack, check_notes = _slack_for_check(check, results[check.id])
        slack.extend(check_slack)
        notes.extend(check_notes)
    return slack, notes


def _worklist_report(
    root: Path, config: Config, check_ids: list[str]
) -> tuple[int, list[Row], list[Slack], list[Note]]:
    selected = _select_checks(config, check_ids)
    if not selected:
        return 0, [], [], []
    try:
        inventory, results, order = _run_selected(root, config, selected)
    except UsageError:
        raise
    except (GateError, OSError) as error:
        print(f"worklist: {error}", file=sys.stderr)
        return 1, [], [], []
    failure = _selected_failure(inventory, results, order)
    if failure is not None:
        print(_failure_message(failure), file=sys.stderr)
        return 1, [], [], []
    try:
        rows, notes = _collect(root, selected, results)
        slack, slack_notes = _collect_slack(selected, results)
    except GateError as error:
        print(f"worklist: {error}", file=sys.stderr)
        return 1, [], [], []
    rows.sort(key=lambda row: row.product, reverse=True)
    return 0, rows, slack, notes + slack_notes


def _note_text(note: Note) -> str:
    if note.file is None:
        return note.reason
    return f"{note.reason} ({note.file})"


def _print_report(rows: list[Row], slack: list[Slack], notes: list[Note]) -> None:
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
    if slack:
        _print_slack(slack)
    if notes:
        _print_notes(notes)


def _print_slack(slack: list[Slack]) -> None:
    print("")
    print("Minimum bounds:")
    print(f"{'BOUND':>7} {'VALUE':>7} {'SLACK':>7}  CHECK  SUBJECT")
    for item in slack:
        print(f"{item.bound:>7.1f} {item.value:>7.1f} {item.amount:>7.1f}  "
              f"{item.check}  {item.subject}")


def _print_notes(notes: list[Note]) -> None:
    print("")
    print("Not ranked:")
    for note in notes:
        print(f"  {note.check}: {note.subject}: {_note_text(note)}")


def _document(rows: list[Row], slack: list[Slack], notes: list[Note]) -> dict[str, Any]:
    return {
        "schema": 1,
        "rows": [row.to_json() for row in rows],
        "slack": [item.to_json() for item in slack],
        "notes": [note.to_json() for note in notes],
    }


def command_worklist(
    root: Path, config: Config, check_ids: list[str], json_output: bool
) -> int:
    if json_output:
        with contextlib.redirect_stdout(sys.stderr):
            code, rows, slack, notes = _worklist_report(root, config, check_ids)
        if code == 0:
            print(
                json.dumps(_document(rows, slack, notes), indent=2, allow_nan=False)
            )
        return code
    code, rows, slack, notes = _worklist_report(root, config, check_ids)
    if code == 0:
        _print_report(rows, slack, notes)
    return code
