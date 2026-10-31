"""The churn x current-value worklist for reasoned baseline entries."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .adapters import adapter_for
from .checks import CheckResult, _inventory_check, _test_check_dependencies, run_check
from .files import _type_name, enumerate_files, git_argv
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


def _require_distinct(identifiers: list[str]) -> None:
    seen: set[str] = set()
    for identifier in identifiers:
        if identifier in seen:
            raise UsageError(f"qg.py worklist: duplicate check id {identifier!r}")
        seen.add(identifier)


def _select_checks(config: Config, identifiers: list[str]) -> list[CheckDef]:
    _require_distinct(identifiers)
    if identifiers:
        return [
            _requested_check(config, identifier) for identifier in identifiers
        ]
    return [check for check in config.checks.values() if _qualifies(check)]


def _required(config: Config, check: CheckDef) -> list[str]:
    descriptor = adapter_for(check.adapter)
    assert descriptor is not None
    if descriptor.requires_tests:
        prior: dict[str, CheckDef] = {}
        for candidate in config.checks.values():
            if candidate.id == check.id:
                break
            prior[candidate.id] = candidate
        return _test_check_dependencies(check, prior)
    required = getattr(check.spec, "requires", None)
    return [required] if required is not None else []


def _needed_order(config: Config, selected: list[CheckDef]) -> list[str]:
    needed = {check.id for check in selected}
    for check in reversed(list(config.checks.values())):
        if check.id in needed:
            needed.update(_required(config, check))
    return _policy_order(config, needed)


def _policy_order(config: Config, needed: set[str]) -> list[str]:
    return [identifier for identifier in config.checks if identifier in needed]


def _expect_git(result: RunResult, action: str) -> None:
    if result.execution != "completed" or result.returncode != 0:
        detail = (
            result.stderr_text.strip() or result.error
            or f"{result.execution} (exit {result.returncode})"
        )
        raise GateError(f"{action}: {detail}")


def _copy_git_path(root: Path, name: str) -> Path:
    result = run(
        git_argv(root, "rev-parse", "--path-format=absolute", "--git-path", name),
        budget_seconds=GIT_BUDGET_SECONDS, capture_limit=None,
    )
    _expect_git(result, f"cannot locate Git {name}")
    return Path(os.fsdecode(result.stdout).rstrip("\n"))


def _copy_index_objects(root: Path, destination: Path) -> None:
    pack = destination / ".git" / "objects" / "pack" / "worklist-index"
    result = run(
        git_argv(root, "pack-objects", "--revs", "--indexed-objects", "--non-empty",
                 "--quiet", str(pack)),
        budget_seconds=600,
    )
    _expect_git(result, "cannot copy staged Git objects")


def _clone_repository(root: Path, destination: Path) -> None:
    result = run(
        git_argv(root, "clone", "--quiet", "--no-local", "--no-hardlinks", "--no-checkout",
                 "--", str(root), str(destination)),
        budget_seconds=600,
    )
    _expect_git(result, "cannot copy Git repository")


def _copy_index(root: Path, destination: Path) -> None:
    index = _copy_git_path(root, "index")
    if index.exists():
        _copy_index_objects(root, destination)
        shutil.copy2(index, destination / ".git" / "index")
        for shared in index.parent.glob("sharedindex.*"):
            shutil.copy2(shared, destination / ".git" / shared.name)


def _copy_exclude(root: Path, destination: Path) -> None:
    exclude = _copy_git_path(root, "info/exclude")
    if exclude.exists():
        shutil.copy2(exclude, destination / ".git" / "info" / "exclude")


def _enumeration_config(root: Path, key: str) -> str | None:
    value_type = "--path" if key == "core.excludesFile" else "--bool"
    result = run(
        git_argv(root, "config", "--null", value_type, "--get", key),
        budget_seconds=GIT_BUDGET_SECONDS, capture_limit=None,
    )
    if result.execution == "completed" and result.returncode == 1:
        return None
    _expect_git(result, f"cannot read Git configuration {key}")
    return os.fsdecode(result.stdout).removesuffix("\0")


def _copy_enumeration_config(root: Path, destination: Path) -> None:
    # Read effective values, including local includes and worktree configuration.
    # These control excludes, filename matching and deleted-file detection.
    for key in ("core.excludesFile", "core.ignoreCase", "core.precomposeUnicode", "core.symlinks"):
        value = _enumeration_config(root, key)
        if value is None:
            continue
        if key == "core.excludesFile" and value:
            value = os.path.abspath(root / value)
        result = run(
            git_argv(destination, "config", "--local", key, value),
            budget_seconds=GIT_BUDGET_SECONDS,
        )
        _expect_git(result, f"cannot copy Git configuration {key}")


def _copy_regular_file(source: str, destination: str) -> str:
    mode = Path(source).lstat().st_mode
    if not stat.S_ISREG(mode):
        kind = _type_name(mode) or stat.filemode(mode)
        raise GateError(f"cannot copy repository path {source}: unsupported file type {kind}")
    return shutil.copy2(source, destination)


def _compare_enumeration(root: Path, destination: Path) -> None:
    original = Counter(enumerate_files(root))
    copied = Counter(enumerate_files(destination))
    if original != copied:
        missing = sorted((original - copied).elements())
        added = sorted((copied - original).elements())
        raise GateError(
            f"copy inventory differs from original: missing paths {missing!r}; added paths {added!r}"
        )


def _copy_tree(root: Path, destination: Path) -> None:
    _clone_repository(root, destination)
    try:
        shutil.copytree(root, destination, dirs_exist_ok=True, symlinks=True,
                        copy_function=_copy_regular_file, ignore=shutil.ignore_patterns(".git"))
        _copy_index(root, destination)
        _copy_exclude(root, destination)
        _copy_enumeration_config(root, destination)
        _compare_enumeration(root, destination)
    except (OSError, shutil.Error) as error:
        raise GateError(f"cannot copy repository {root}: {error}") from error


def _copy_config(config: Config, root: Path) -> Config:
    checks: dict[str, CheckDef] = {}
    for check in config.checks.values():
        baseline = check.baseline
        if baseline is not None:
            path = Path(os.path.abspath(baseline))
            if path.is_relative_to(config.root):
                baseline = root / path.relative_to(config.root)
        checks[check.id] = replace(check, baseline=baseline)
    return replace(config, root=root, path=root / config.path.name, checks=checks)


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


def _run_copied(
    root: Path, config: Config, selected: list[CheckDef]
) -> tuple[CheckResult, dict[str, CheckResult], list[str]]:
    _reject_original_arguments(root, config, selected)
    with tempfile.TemporaryDirectory(prefix="qg-worklist-") as temporary:
        copied_root = Path(temporary) / "repo"
        _copy_tree(root, copied_root)
        copied_config = _copy_config(config, copied_root)
        copied_checks = [copied_config.checks[check.id] for check in selected]
        return _run_selected(copied_root, copied_config, copied_checks)


def _original_argument_target(root: Path, argument: str, identifier: str) -> Path | None:
    values = (argument, argument.partition("=")[2]) if argument.startswith("--") else (argument,)
    for value in values:
        path = Path(value)
        if path.is_absolute():
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError, ValueError) as error:
                raise GateError(
                    f"check {identifier!r}: cannot resolve argument {argument!r}: {error}"
                ) from error
            if resolved.is_relative_to(root):
                return resolved
    return None


def _reject_original_arguments(root: Path, config: Config, selected: list[CheckDef]) -> None:
    canonical_root = root.resolve()
    paths = {str(root.absolute()), str(canonical_root)}
    for identifier in _needed_order(config, selected):
        check = config.checks[identifier]
        descriptor = adapter_for(check.adapter)
        assert descriptor is not None
        for argument in descriptor.arguments(check.spec):
            if any(path in argument for path in paths):
                raise GateError(
                    f"check {identifier!r}: argument {argument!r} contains the original repository's "
                    "absolute path; use a repository-relative path"
                )
            target = _original_argument_target(canonical_root, argument, identifier)
            if target is not None:
                raise GateError(
                    f"check {identifier!r}: argument {argument!r} resolves into the original "
                    f"repository at {str(target)!r}; use a repository-relative path"
                )


def _worklist_report(
    root: Path, config: Config, check_ids: list[str]
) -> tuple[int, list[Row], list[Slack], list[Note]]:
    selected = _select_checks(config, check_ids)
    if not selected:
        return 0, [], [], []
    try:
        inventory, results, order = _run_copied(root, config, selected)
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
