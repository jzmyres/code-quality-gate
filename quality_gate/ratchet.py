"""The generic reasoned ratchet: baselines, decisions, pruning and writing."""
from __future__ import annotations

import datetime
import json
import math
import os
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .policy import GateError, UnsupportedError, _describe


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}

    def __str__(self) -> str:
        if self.start_line == self.end_line:
            return f"{self.path}:{self.start_line}"
        return f"{self.path}:{self.start_line}-{self.end_line}"


@dataclass(frozen=True)
class Finding:
    subject: str
    value: float
    location: str
    measurement: dict[str, Any] | None = None
    locations: tuple[Location, ...] | None = None
    kind: str = "metric"


@dataclass(frozen=True)
class Domain:
    """The subjects one complete measurement covered.

    A file domain matches subjects whose `PATH` prefix is one of the
    measured files (CRAP's `PATH:Qualified.name` subjects).  A subject
    domain lists the subjects one scan measured (clone fingerprints bound to
    their files).  `all` is for a scan whose own completeness proves the
    absence of every subject.
    """

    files: tuple[str, ...] | None = None
    description: str = "all measured subjects"
    subjects: tuple[str, ...] | None = None

    @classmethod
    def all(cls, description: str = "the complete subject domain") -> "Domain":
        return cls(None, description)

    @classmethod
    def of_files(
        cls, files: list[str] | tuple[str, ...], description: str = "the selected files"
    ) -> "Domain":
        return cls(tuple(files), description)

    @classmethod
    def of_subjects(
        cls,
        subjects: list[str] | tuple[str, ...],
        description: str = "the measured subjects",
    ) -> "Domain":
        return cls(None, description, tuple(subjects))

    def contains(self, subject: str) -> bool:
        if self.subjects is not None:
            return subject in self.subjects
        if self.files is None:
            return True
        return subject.rpartition(":")[0] in self.files


@dataclass(frozen=True)
class BaselineEntry:
    subject: str
    bound: float
    reason: str
    expires: datetime.date | None = None
    extras: dict[str, Any] = field(default_factory=dict)
    direction: str = "max"


@dataclass
class FindingResult:
    subject: str
    value: float
    bound: float | None
    threshold: float
    baseline_reason: str | None
    blocking: bool
    location: str
    covered_by_baseline: bool = False
    expired: bool = False
    error: str | None = None
    measurement: dict[str, Any] | None = None
    locations: tuple[Location, ...] | None = None
    on_changed_lines: bool | None = None
    change_scope_evaluated: bool = False
    direction: str = "max"

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "subject": self.subject,
            "value": self.value,
            "bound": self.bound,
            "threshold": self.threshold,
            "baseline_reason": self.baseline_reason,
            "covered_by_baseline": self.covered_by_baseline,
            "blocking": self.blocking,
            "location": self.location,
            "expired": self.expired,
        }
        if self.error is not None:
            result["error"] = self.error
        if self.measurement is not None:
            result["measurement"] = self.measurement
        result["locations"] = (
            [location.to_json() for location in self.locations]
            if self.locations is not None else None
        )
        if self.change_scope_evaluated:
            result["on_changed_lines"] = self.on_changed_lines
        return result


@dataclass
class RatchetResult:
    findings: list[FindingResult]
    resolved: list[str]
    unmeasured: list[str]
    entries: list[BaselineEntry]
    measured: dict[str, float]
    outcome: str
    satisfied: bool
    exceptions: bool
    direction: str = "max"
    adapter: str = "metric"


@dataclass
class _Verdict:
    result: FindingResult
    failure: str | None = None
    raw_failure: bool = False
    blocking_failure: bool = False
    resolved: bool = False
    exception: bool = False
    unmeasured: bool = False


@dataclass
class _Evaluation:
    measured: dict[str, float]
    results: list[FindingResult]
    resolved: list[str]
    unmeasured: list[str]
    failures: list[str]
    raw_failure: bool
    blocking_failure: bool
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


def _read_baseline(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise GateError(f"cannot read baseline {path}: {error}") from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise GateError(f"invalid baseline {path}: {error}") from error


def _check_header(
    path: Path, data: dict[str, Any], check_id: str, metric_version: str
) -> None:
    expected = {"check": check_id, "metric_version": metric_version}
    for key, want in expected.items():
        value = data.get(key)
        where = f"{want!r} (the configured check)"
        if not isinstance(value, str) or not value.strip():
            raise _baseline_error(
                path,
                key,
                where,
                "missing" if value is None else _describe(value),
            )
        if value != want:
            raise _baseline_error(path, key, where, f"{value!r}")


def _validate_extra(
    path: Path, where: str, name: str, value: Any
) -> None:
    if (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    ):
        return
    raise _baseline_error(
        path,
        f"{where}.{name}",
        "a list of strings",
        _describe(value),
    )


def _extras(
    path: Path,
    where: str,
    raw: dict[str, Any],
    allowed_extras: tuple[str, ...],
) -> dict[str, Any]:
    extras = {key: raw[key] for key in allowed_extras if key in raw}
    for name, value in extras.items():
        _validate_extra(path, where, name, value)
    return extras


def _entry_subject(path: Path, where: str, raw: dict[str, Any]) -> str:
    subject = raw.get("subject")
    if isinstance(subject, str) and subject.strip():
        return subject
    raise _baseline_error(
        path,
        f"{where}.subject",
        "a non-empty string",
        "missing" if subject is None else _describe(subject),
    )


def _entry_bound(path: Path, where: str, raw: dict[str, Any]) -> float:
    bound = raw.get("bound")
    if _is_number(bound) and math.isfinite(bound):
        return bound
    raise _baseline_error(
        path,
        f"{where}.bound",
        "a finite number",
        "missing" if bound is None else _describe(bound),
    )


def _entry_reason(path: Path, where: str, raw: dict[str, Any]) -> str:
    reason = raw.get("reason", "")
    if isinstance(reason, str):
        return reason
    raise _baseline_error(
        path, f"{where}.reason", "a string", _describe(reason)
    )


def _entry_expires(
    path: Path, where: str, raw: dict[str, Any]
) -> datetime.date | None:
    if "expires" not in raw:
        return None
    expires = _date_value(raw["expires"])
    if expires is not None:
        return expires
    raise _baseline_error(
        path,
        f"{where}.expires",
        "a TOML date",
        _describe(raw["expires"]),
    )


def _parse_baseline_entry(
    path: Path,
    where: str,
    raw: Any,
    allowed_extras: tuple[str, ...],
) -> BaselineEntry:
    if not isinstance(raw, dict):
        raise _baseline_error(path, where, "a table", _describe(raw))
    allowed = ("subject", "bound", "reason", "expires", *allowed_extras)
    for key in raw:
        if key not in allowed:
            raise _baseline_error(
                path,
                f"{where}.{key}",
                f"a known key ({', '.join(allowed)})",
                "unknown key",
            )
    return BaselineEntry(
        _entry_subject(path, where, raw),
        _entry_bound(path, where, raw),
        _entry_reason(path, where, raw),
        _entry_expires(path, where, raw),
        _extras(path, where, raw, allowed_extras),
    )


def load_baseline(
    path: Path,
    *,
    check_id: str,
    metric_version: str,
    allowed_extras: tuple[str, ...] = (),
    adapter: Any = None,
    direction: str = "max",
) -> list[BaselineEntry]:
    data = _read_baseline(path)
    if data is None:
        return []
    for key in data:
        if key not in ("check", "metric_version", "entry"):
            raise GateError(
                f"{path}: {key}: unknown key; allowed keys: check, "
                "metric_version, entry"
            )
    _check_header(path, data, check_id, metric_version)
    raw_entries = data.get("entry", [])
    if not isinstance(raw_entries, list):
        raise _baseline_error(
            path, "entry", "an array of tables", _describe(raw_entries)
        )
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        entry = _parse_baseline_entry(
            path, f"entry[{index}]", raw, allowed_extras
        )
        entry = replace(
            entry,
            direction=subject_direction(adapter, direction, entry.subject),
        )
        if entry.subject in seen:
            raise _baseline_error(
                path,
                f"entry[{index}].subject",
                "a unique subject",
                f"duplicate {entry.subject!r}",
            )
        seen.add(entry.subject)
        entries.append(entry)
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
        if not math.isfinite(value):
            raise GateError("cannot write a non-finite baseline value")
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


def write_baseline(
    path: Path,
    entries: list[BaselineEntry],
    *,
    check_id: str,
    metric_version: str,
) -> bytes | None:
    if not entries:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise GateError(f"cannot remove empty baseline {path}: {error}") from error
        return None
    lines = [
        f"check = {_toml_value(check_id)}",
        f"metric_version = {_toml_value(metric_version)}",
        "",
        "# Reasoned ratchet baseline: each entry accepts a measured subject up to",
        "# its bound, for the stated reason. Add entries by hand; --prune only",
        "# tightens bounds (lowers a max bound, raises a min bound) and removes",
        "# resolved entries.",
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
    text = "\n".join(lines)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=str(path.parent)
        )
    except OSError as error:
        raise GateError(f"cannot write baseline {path}: {error}") from error
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise GateError(f"cannot write baseline {path}: {error}") from error
    return text.encode("utf-8")


def _descriptor(adapter: Any) -> Any:
    from .adapters import adapter_for

    return adapter_for(adapter)


def _subject_label(subject: str, adapter: Any, has_entry: bool) -> str:
    descriptor = _descriptor(adapter)
    if descriptor is None or not descriptor.subject_noun:
        return subject
    label = f"{descriptor.subject_noun} {subject}"
    return label if has_entry else f"new {label}"


def _display_number(value: float, adapter: Any) -> str:
    descriptor = _descriptor(adapter)
    if descriptor is not None:
        return descriptor.display(value)
    return _number(value)


def subject_direction(adapter: Any, direction: str, subject: str) -> str:
    descriptor = _descriptor(adapter)
    if descriptor is None:
        return direction
    return descriptor.direction_for_subject(subject, direction)


def _within(value: float, bound: float, direction: str) -> bool:
    if direction == "min":
        return value >= bound
    return value <= bound


def _outside(value: float, threshold: float, direction: str) -> bool:
    if direction == "min":
        return value < threshold
    return value > threshold


def tighter_bound(revision: float, candidate: float, direction: str) -> float:
    if direction == "min":
        return max(revision, candidate)
    return min(revision, candidate)


def _expiry_detail(entry: BaselineEntry | None, expired: bool) -> str:
    if expired and entry is not None and entry.expires is not None:
        return f" (baseline entry expired {entry.expires.isoformat()})"
    return ""


def _occurrence_detail(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    threshold: float,
) -> str:
    times = "time" if finding.value == 1 else "times"
    detail = (
        f"occurs {_number(finding.value)} {times}, exceeding threshold "
        f"{_number(threshold)}"
    )
    if entry is not None and not expired:
        detail += f" and baseline bound {_number(entry.bound)}"
    return detail + _expiry_detail(entry, expired)


def _min_detail(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    threshold: float,
    adapter: str,
) -> str:
    value = _display_number(finding.value, adapter)
    if entry is None:
        return f"value {value} has no baseline floor"
    detail = (
        f"value {value} falls below baseline bound "
        f"{_display_number(entry.bound, adapter)}"
    )
    return detail + _expiry_detail(entry, expired)


def _metric_detail(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    threshold: float,
    adapter: str,
    direction: str,
) -> str:
    if direction == "min":
        return _min_detail(finding, entry, expired, threshold, adapter)
    detail = (
        f"value {_display_number(finding.value, adapter)} exceeds "
        f"threshold {_display_number(threshold, adapter)}"
    )
    if entry is not None and not expired:
        detail += (
            " and baseline bound "
            f"{_display_number(entry.bound, adapter)}"
        )
    return detail + _expiry_detail(entry, expired)


def _format_failure(
    prefix: str,
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    threshold: float,
    adapter: str,
    direction: str = "max",
) -> str:
    label = _subject_label(finding.subject, adapter, entry is not None)
    descriptor = _descriptor(adapter)
    if descriptor is not None and descriptor.failure_wording == "occurrences":
        detail = _occurrence_detail(finding, entry, expired, threshold)
    else:
        detail = _metric_detail(
            finding, entry, expired, threshold, adapter, direction
        )
    return f"{prefix}: {label}: {detail} at {finding.location}"


def _require_finite(value: float, message: str) -> None:
    if not math.isfinite(value):
        raise UnsupportedError(message)


def _finite_inputs(
    findings: list[Finding],
    entries: list[BaselineEntry],
    threshold: float,
    prefix: str,
) -> None:
    _require_finite(threshold, f"{prefix}: non-finite threshold {threshold!r}")
    for entry in entries:
        _require_finite(
            entry.bound,
            f"{prefix}: baseline entry {entry.subject}: non-finite "
            f"bound {entry.bound!r}",
        )
    for finding in findings:
        _require_finite(
            finding.value,
            f"{prefix}: {finding.subject}: non-finite measured value "
            f"{finding.value!r}",
        )


def _empty_reason_detail(entry: BaselineEntry) -> str:
    return "".join(
        f" ({name}: {', '.join(value)})"
        for name, value in entry.extras.items()
        if isinstance(value, list) and value
    )


def _scan_entries(
    entries: list[BaselineEntry],
    today: datetime.date,
    enforcement: str,
    prefix: str,
) -> tuple[set[str], set[str], list[str], bool, bool]:
    expired: set[str] = set()
    empty: set[str] = set()
    failures: list[str] = []
    raw_failure = False
    blocking_failure = False
    for entry in entries:
        if not entry.reason.strip():
            empty.add(entry.subject)
            failures.append(
                f"{prefix}: baseline entry {entry.subject}: empty reason "
                f"(expected a non-empty reason){_empty_reason_detail(entry)}"
            )
            raw_failure = True
            if enforcement == "enforced":
                blocking_failure = True
        if entry.expires is not None and entry.expires < today:
            expired.add(entry.subject)
            print(
                f"{prefix}: expired baseline entry {entry.subject} "
                f"(expired {entry.expires.isoformat()})"
            )
    return expired, empty, failures, raw_failure, blocking_failure


def _record_unmeasured(
    entries: list[BaselineEntry],
    measured: dict[str, float],
    empty: set[str],
    expired: set[str],
    enforcement: str,
    threshold: float,
    domain: Domain,
    results: list[FindingResult],
    resolved: list[str],
    unmeasured: list[str],
) -> None:
    for entry in entries:
        if entry.subject in measured:
            continue
        if entry.subject in empty:
            results.append(
                FindingResult(
                    subject=entry.subject,
                    value=0,
                    bound=entry.bound,
                    threshold=threshold,
                    baseline_reason=entry.reason,
                    blocking=enforcement == "enforced",
                    location="baseline",
                    covered_by_baseline=False,
                    expired=entry.subject in expired,
                    error="empty baseline reason",
                    direction=entry.direction,
                )
            )
        if domain.contains(entry.subject):
            resolved.append(entry.subject)
        else:
            unmeasured.append(entry.subject)


def _missing_min(
    finding: Finding,
    threshold: float,
    enforcement: str,
    prefix: str,
) -> _Verdict:
    reason = "unmeasured: no baseline entry for a min metric"
    message = (
        f"{prefix}: {finding.subject}: {reason} "
        f"(measured {_number(finding.value)} at {finding.location})"
    )
    result = FindingResult(
        subject=finding.subject,
        value=finding.value,
        bound=None,
        threshold=threshold,
        baseline_reason=None,
        blocking=enforcement == "enforced",
        location=finding.location,
        covered_by_baseline=False,
        expired=False,
        error=reason,
        measurement=finding.measurement,
        locations=finding.locations,
        direction="min",
    )
    return _Verdict(
        result=result,
        failure=message,
        raw_failure=True,
        blocking_failure=enforcement == "enforced",
        unmeasured=True,
    )


def _valid_entry(
    entry: BaselineEntry | None,
    value: float,
    direction: str,
    expired: bool,
) -> bool:
    if entry is None or expired:
        return False
    if not entry.reason.strip():
        return False
    return _within(value, entry.bound, direction)


def _finding_result(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    valid_entry: bool,
    blocking: bool,
    empty_reason_subjects: set[str],
    threshold: float,
    enforcement: str,
    direction: str,
) -> FindingResult:
    result = FindingResult(
        subject=finding.subject,
        value=finding.value,
        bound=entry.bound if entry is not None else None,
        threshold=threshold,
        baseline_reason=entry.reason if entry is not None else None,
        blocking=blocking,
        location=finding.location,
        covered_by_baseline=valid_entry,
        expired=expired,
        measurement=finding.measurement,
        locations=finding.locations,
        direction=direction,
    )
    if finding.subject in empty_reason_subjects:
        result.blocking = enforcement == "enforced"
        result.error = "empty baseline reason"
    return result


def _verdict_failure(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    passes: bool,
    empty_reason_subjects: set[str],
    threshold: float,
    adapter: str,
    direction: str,
    prefix: str,
) -> str | None:
    if finding.subject in empty_reason_subjects:
        return (
            f"{prefix}: baseline entry {finding.subject}: empty reason "
            f"at {finding.location}"
        )
    if passes:
        return None
    return _format_failure(
        prefix, finding, entry, expired, threshold, adapter, direction
    )


def _max_verdict(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    empty_reason_subjects: set[str],
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
) -> _Verdict:
    outside = _outside(finding.value, threshold, "max")
    valid = _valid_entry(entry, finding.value, "max", expired)
    passes = (not outside) or valid
    blocking = (not passes) and enforcement == "enforced"
    result = _finding_result(
        finding,
        entry,
        expired,
        valid,
        blocking,
        empty_reason_subjects,
        threshold,
        enforcement,
        "max",
    )
    failure = _verdict_failure(
        finding,
        entry,
        expired,
        passes,
        empty_reason_subjects,
        threshold,
        adapter,
        "max",
        prefix,
    )
    return _Verdict(
        result=result,
        failure=failure,
        raw_failure=outside,
        blocking_failure=blocking or result.blocking,
        resolved=entry is not None and not outside,
        exception=outside and valid,
    )


def _min_verdict(
    finding: Finding,
    entry: BaselineEntry | None,
    expired: bool,
    empty_reason_subjects: set[str],
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
) -> _Verdict:
    valid = _valid_entry(entry, finding.value, "min", expired)
    blocking = (not valid) and enforcement == "enforced"
    result = _finding_result(
        finding,
        entry,
        expired,
        valid,
        blocking,
        empty_reason_subjects,
        threshold,
        enforcement,
        "min",
    )
    failure = _verdict_failure(
        finding,
        entry,
        expired,
        valid,
        empty_reason_subjects,
        threshold,
        adapter,
        "min",
        prefix,
    )
    return _Verdict(
        result=result,
        failure=failure,
        raw_failure=not valid,
        blocking_failure=blocking or result.blocking,
    )


def _evaluate_finding(
    finding: Finding,
    by_subject: dict[str, BaselineEntry],
    expired_subjects: set[str],
    empty_reason_subjects: set[str],
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
    direction: str,
) -> _Verdict:
    direction = subject_direction(adapter, direction, finding.subject)
    entry = by_subject.get(finding.subject)
    if direction == "min":
        if entry is None:
            return _missing_min(
                finding, threshold, enforcement, prefix
            )
        return _min_verdict(
            finding,
            entry,
            finding.subject in expired_subjects,
            empty_reason_subjects,
            threshold,
            enforcement,
            prefix,
            adapter,
        )
    return _max_verdict(
        finding,
        entry,
        finding.subject in expired_subjects,
        empty_reason_subjects,
        threshold,
        enforcement,
        prefix,
        adapter,
    )


def _accumulate_verdict(
    verdict: _Verdict,
    results: list[FindingResult],
    resolved: list[str],
    unmeasured: list[str],
    failures: list[str],
) -> None:
    results.append(verdict.result)
    if verdict.failure is not None:
        failures.append(verdict.failure)
    if verdict.resolved:
        resolved.append(verdict.result.subject)
    if verdict.unmeasured:
        unmeasured.append(verdict.result.subject)


def _report(
    prefix: str,
    failures: list[str],
    resolved: list[str],
    unmeasured: list[str],
    by_subject: dict[str, BaselineEntry],
    domain: Domain,
) -> None:
    for message in failures:
        print(message, file=sys.stderr)
    for subject in resolved:
        print(f"{prefix}: resolved {subject}")
    for subject in unmeasured:
        if subject in by_subject:
            print(
                f"{prefix}: unmeasured {subject} (outside "
                f"{domain.description}); kept"
            )


def _evaluate_all(
    findings: list[Finding],
    by_subject: dict[str, BaselineEntry],
    expired_subjects: set[str],
    empty_reason_subjects: set[str],
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
    direction: str,
    failures: list[str],
    raw_failure: bool,
    blocking_failure: bool,
) -> _Evaluation:
    measured: dict[str, float] = {}
    results: list[FindingResult] = []
    resolved: list[str] = []
    unmeasured: list[str] = []
    exceptions = False
    for finding in findings:
        if finding.subject in measured:
            raise GateError(
                f"{prefix}: duplicate measured subject {finding.subject!r}"
            )
        measured[finding.subject] = finding.value
        verdict = _evaluate_finding(
            finding,
            by_subject,
            expired_subjects,
            empty_reason_subjects,
            threshold,
            enforcement,
            prefix,
            adapter,
            direction,
        )
        _accumulate_verdict(
            verdict, results, resolved, unmeasured, failures
        )
        raw_failure |= verdict.raw_failure
        blocking_failure |= verdict.blocking_failure
        exceptions |= verdict.exception
    return _Evaluation(
        measured=measured,
        results=results,
        resolved=resolved,
        unmeasured=unmeasured,
        failures=failures,
        raw_failure=raw_failure,
        blocking_failure=blocking_failure,
        exceptions=exceptions,
    )


def evaluate(
    findings: list[Finding],
    entries: list[BaselineEntry],
    *,
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: Any,
    domain: Domain,
    today: datetime.date | None = None,
    direction: str = "max",
) -> RatchetResult:
    today = today or datetime.date.today()
    _finite_inputs(findings, entries, threshold, prefix)
    entries = [
        replace(
            entry,
            direction=subject_direction(adapter, direction, entry.subject),
        )
        for entry in entries
    ]
    by_subject = {entry.subject: entry for entry in entries}
    (
        expired_subjects,
        empty_reason_subjects,
        failures,
        raw_failure,
        blocking_failure,
    ) = _scan_entries(entries, today, enforcement, prefix)
    evaluation = _evaluate_all(
        findings,
        by_subject,
        expired_subjects,
        empty_reason_subjects,
        threshold,
        enforcement,
        prefix,
        adapter,
        direction,
        failures,
        raw_failure,
        blocking_failure,
    )
    _record_unmeasured(
        entries,
        evaluation.measured,
        empty_reason_subjects,
        expired_subjects,
        enforcement,
        threshold,
        domain,
        evaluation.results,
        evaluation.resolved,
        evaluation.unmeasured,
    )
    _report(
        prefix,
        evaluation.failures,
        evaluation.resolved,
        evaluation.unmeasured,
        by_subject,
        domain,
    )
    return RatchetResult(
        findings=evaluation.results,
        resolved=evaluation.resolved,
        unmeasured=evaluation.unmeasured,
        entries=entries,
        measured=evaluation.measured,
        outcome="fail" if evaluation.raw_failure else "pass",
        satisfied=not evaluation.blocking_failure,
        exceptions=evaluation.exceptions,
        direction=direction,
        adapter=adapter,
    )


def _prune_entry(
    entry: BaselineEntry, value: float, result: RatchetResult
) -> BaselineEntry:
    direction = entry.direction
    if direction == "min":
        return replace(entry, bound=max(entry.bound, value))
    return replace(entry, bound=min(entry.bound, value))


def pruned_entries(result: RatchetResult) -> list[BaselineEntry]:
    if not result.satisfied:
        raise GateError("cannot prune while the check fails")
    resolved = set(result.resolved)
    unmeasured = set(result.unmeasured)
    pruned: list[BaselineEntry] = []
    for entry in result.entries:
        if entry.subject in resolved:
            continue
        value = result.measured.get(entry.subject)
        if value is None:
            if entry.subject in unmeasured:
                pruned.append(entry)
            continue
        pruned.append(_prune_entry(entry, value, result))
    return pruned
