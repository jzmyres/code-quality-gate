"""The generic reasoned ratchet: baselines, decisions, pruning and writing."""
from __future__ import annotations

import datetime
import json
import os
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .policy import GateError, _describe


@dataclass(frozen=True)
class Finding:
    subject: str
    value: float
    location: str


@dataclass(frozen=True)
class BaselineEntry:
    subject: str
    bound: float
    reason: str
    expires: datetime.date | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingResult:
    subject: str
    value: float
    bound: float | None
    threshold: float
    baseline_reason: str | None
    blocking: bool
    location: str
    expired: bool = False
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "subject": self.subject,
            "value": self.value,
            "bound": self.bound,
            "threshold": self.threshold,
            "baseline_reason": self.baseline_reason,
            "blocking": self.blocking,
            "location": self.location,
            "expired": self.expired,
        }
        if self.error is not None:
            result["error"] = self.error
        return result


@dataclass
class RatchetResult:
    findings: list[FindingResult]
    resolved: list[str]
    entries: list[BaselineEntry]
    measured: dict[str, float]
    outcome: str
    exceptions: bool


def _baseline_error(path: Path, key: str, expected: str, actual: str) -> GateError:
    return GateError(f"{path}: {key}: expected {expected}, got {actual}")


def _is_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _date_value(value: object) -> datetime.date | None:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    return None


def load_baseline(
    path: Path, *, allowed_extras: tuple[str, ...] = ()
) -> list[BaselineEntry]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise GateError(f"cannot read baseline {path}: {error}") from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise GateError(f"invalid baseline {path}: {error}") from error

    for key in data:
        if key != "entry":
            raise GateError(
                f"{path}: {key}: unknown key; allowed keys: entry"
            )
    raw_entries = data.get("entry", [])
    if not isinstance(raw_entries, list):
        raise _baseline_error(path, "entry", "an array of tables", _describe(raw_entries))
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    common = ("subject", "bound", "reason", "expires")
    for index, raw in enumerate(raw_entries):
        where = f"entry[{index}]"
        if not isinstance(raw, dict):
            raise _baseline_error(path, where, "a table", _describe(raw))
        allowed = (*common, *allowed_extras)
        for key in raw:
            if key not in allowed:
                names = ", ".join(allowed)
                raise _baseline_error(
                    path,
                    f"{where}.{key}",
                    f"a known key ({names})",
                    "unknown key",
                )
        subject = raw.get("subject")
        if not isinstance(subject, str) or not subject.strip():
            raise _baseline_error(
                path,
                f"{where}.subject",
                "a non-empty string",
                "missing" if subject is None else _describe(subject),
            )
        if subject in seen:
            raise _baseline_error(
                path,
                f"{where}.subject",
                "a unique subject",
                f"duplicate {subject!r}",
            )
        seen.add(subject)
        bound = raw.get("bound")
        if not _is_number(bound):
            raise _baseline_error(
                path,
                f"{where}.bound",
                "a number",
                "missing" if bound is None else _describe(bound),
            )
        reason = raw.get("reason", "")
        if not isinstance(reason, str):
            raise _baseline_error(
                path, f"{where}.reason", "a string", _describe(reason)
            )
        expires: datetime.date | None = None
        if "expires" in raw:
            expires = _date_value(raw["expires"])
            if expires is None:
                raise _baseline_error(
                    path,
                    f"{where}.expires",
                    "a TOML date",
                    _describe(raw["expires"]),
                )
        extras = {
            key: raw[key]
            for key in allowed_extras
            if key in raw
        }
        if "files" in extras and (
            not isinstance(extras["files"], list)
            or any(not isinstance(item, str) for item in extras["files"])
        ):
            raise _baseline_error(
                path,
                f"{where}.files",
                "a list of strings",
                _describe(extras["files"]),
            )
        entries.append(BaselineEntry(subject, bound, reason, expires, extras))
    return entries


def _number(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)
    if value.is_integer():
        return str(int(value))
    return repr(value)


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return "[" + ", ".join(json.dumps(item, ensure_ascii=False) for item in value) + "]"
    raise GateError(f"cannot write baseline value of type {type(value).__name__}")


def write_baseline(path: Path, entries: list[BaselineEntry]) -> None:
    if not entries:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise GateError(f"cannot remove empty baseline {path}: {error}") from error
        return
    lines = [
        "# Reasoned ratchet baseline: each entry accepts a measured subject up to",
        "# its bound, for the stated reason. Add entries by hand; --prune only",
        "# lowers bounds and removes resolved entries.",
        "",
    ]
    for entry in entries:
        lines.append("[[entry]]")
        lines.append(f"subject = {_toml_value(entry.subject)}")
        lines.append(f"bound = {_toml_value(entry.bound)}")
        lines.append(f"reason = {_toml_value(entry.reason)}")
        if entry.expires is not None:
            lines.append(f"expires = {_toml_value(entry.expires)}")
        for key in sorted(entry.extras):
            lines.append(f"{key} = {_toml_value(entry.extras[key])}")
        lines.append("")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=str(path.parent)
        )
    except OSError as error:
        raise GateError(f"cannot write baseline {path}: {error}") from error
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines))
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise GateError(f"cannot write baseline {path}: {error}") from error


def _subject_label(subject: str, adapter: str, has_entry: bool) -> str:
    if adapter == "clones":
        return f"clone {subject}" if has_entry else f"new clone {subject}"
    return subject


def _format_failure(
    prefix: str,
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    threshold: float,
    adapter: str,
) -> str:
    label = _subject_label(finding.subject, adapter, entry is not None)
    if adapter == "clones":
        times = "time" if finding.value == 1 else "times"
        detail = (
            f"occurs {_number(finding.value)} {times}, exceeding threshold "
            f"{_number(threshold)}"
        )
        if entry is not None and not expired:
            detail += f" and baseline bound {_number(entry.bound)}"
        if expired and entry is not None and entry.expires is not None:
            detail += f" (baseline entry expired {entry.expires.isoformat()})"
    else:
        detail = f"value {_number(finding.value)} exceeds threshold {_number(threshold)}"
        if entry is not None and not expired:
            detail += f" and baseline bound {_number(entry.bound)}"
        if expired and entry is not None and entry.expires is not None:
            detail += f" (baseline entry expired {entry.expires.isoformat()})"
    return f"{prefix}: {label}: {detail} at {finding.location}"


def evaluate(
    findings: list[Finding],
    entries: list[BaselineEntry],
    *,
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
    today: datetime.date | None = None,
) -> RatchetResult:
    today = today or datetime.date.today()
    by_subject = {entry.subject: entry for entry in entries}
    measured: dict[str, float] = {}
    failures: list[str] = []
    resolved: list[str] = []
    results: list[FindingResult] = []
    expired_subjects: set[str] = set()
    empty_reason_subjects: set[str] = set()

    for entry in entries:
        if not entry.reason.strip():
            empty_reason_subjects.add(entry.subject)
            detail = ""
            files = entry.extras.get("files")
            if isinstance(files, list) and files:
                detail = f" (files: {', '.join(files)})"
            failures.append(
                f"{prefix}: baseline entry {entry.subject}: empty reason "
                f"(expected a non-empty reason){detail}"
            )
        if entry.expires is not None and entry.expires < today:
            expired_subjects.add(entry.subject)
            print(
                f"{prefix}: expired baseline entry {entry.subject} "
                f"(expired {entry.expires.isoformat()})"
            )

    for finding in findings:
        if finding.subject in measured:
            raise GateError(f"{prefix}: duplicate measured subject {finding.subject!r}")
        measured[finding.subject] = finding.value
        entry = by_subject.get(finding.subject)
        expired = finding.subject in expired_subjects
        threshold_pass = finding.value <= threshold
        covered = (
            entry is not None
            and not expired
            and finding.value <= entry.bound
        )
        passes = threshold_pass or covered
        if entry is not None and threshold_pass:
            resolved.append(entry.subject)
        blocking = (not passes) and enforcement == "enforced"
        if not passes:
            failures.append(
                _format_failure(prefix, finding, entry, expired, threshold, adapter)
            )
        result = FindingResult(
            subject=finding.subject,
            value=finding.value,
            bound=entry.bound if entry is not None else None,
            threshold=threshold,
            baseline_reason=entry.reason if entry is not None else None,
            blocking=blocking,
            location=finding.location,
            expired=expired,
        )
        if finding.subject in empty_reason_subjects:
            result.blocking = enforcement == "enforced"
            result.error = "empty baseline reason"
            failures.append(
                f"{prefix}: baseline entry {finding.subject}: empty reason "
                f"at {finding.location}"
            )
        results.append(result)

    for entry in entries:
        if entry.subject in measured:
            continue
        resolved.append(entry.subject)
        if entry.subject in empty_reason_subjects:
            results.append(
                FindingResult(
                    subject=entry.subject,
                    value=0,
                    bound=entry.bound,
                    threshold=threshold,
                    baseline_reason=entry.reason,
                    blocking=enforcement == "enforced",
                    location="baseline",
                    expired=entry.subject in expired_subjects,
                    error="empty baseline reason",
                )
            )

    for message in failures:
        print(message, file=sys.stderr)
    for subject in resolved:
        print(f"{prefix}: resolved {subject}")

    exceptions = any(
        item.baseline_reason is not None
        and not item.expired
        and item.error is None
        and item.value > threshold
        for item in results
    )
    outcome = "fail" if failures else "pass"
    return RatchetResult(
        findings=results,
        resolved=resolved,
        entries=entries,
        measured=measured,
        outcome=outcome,
        exceptions=exceptions,
    )


def pruned_entries(result: RatchetResult) -> list[BaselineEntry]:
    if result.outcome != "pass":
        raise GateError("cannot prune while the check fails")
    resolved = set(result.resolved)
    pruned: list[BaselineEntry] = []
    for entry in result.entries:
        if entry.subject in resolved:
            continue
        value = result.measured.get(entry.subject)
        if value is None:
            continue
        pruned.append(replace(entry, bound=min(entry.bound, value)))
    return pruned
