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
class Finding:
    subject: str
    value: float
    location: str
    measurement: dict[str, Any] | None = None


@dataclass(frozen=True)
class Domain:
    """The subjects one complete measurement covered.

    A file domain matches subjects whose `PATH` prefix is one of the
    measured files (CRAP's `PATH:Qualified.name` subjects).  `all` is for a
    scan whose own completeness proves the absence of every subject, such
    as a completed jscpd run over the selected files.
    """

    files: tuple[str, ...] | None = None
    description: str = "all measured subjects"

    @classmethod
    def all(cls, description: str = "the complete subject domain") -> "Domain":
        return cls(None, description)

    @classmethod
    def of_files(
        cls, files: list[str] | tuple[str, ...], description: str = "the selected files"
    ) -> "Domain":
        return cls(tuple(files), description)

    def contains(self, subject: str) -> bool:
        if self.files is None:
            return True
        return subject.partition(":")[0] in self.files


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
    covered_by_baseline: bool = False
    expired: bool = False
    error: str | None = None
    measurement: dict[str, Any] | None = None

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


def _validate_files_extra(
    path: Path, where: str, extras: dict[str, Any]
) -> None:
    files = extras.get("files")
    if files is None or (
        isinstance(files, list)
        and all(isinstance(item, str) for item in files)
    ):
        return
    raise _baseline_error(
        path,
        f"{where}.files",
        "a list of strings",
        _describe(files),
    )


def _extras(
    path: Path,
    where: str,
    raw: dict[str, Any],
    allowed_extras: tuple[str, ...],
) -> dict[str, Any]:
    extras = {key: raw[key] for key in allowed_extras if key in raw}
    _validate_files_extra(path, where, extras)
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
) -> None:
    if not entries:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise GateError(f"cannot remove empty baseline {path}: {error}") from error
        return
    lines = [
        f"check = {_toml_value(check_id)}",
        f"metric_version = {_toml_value(metric_version)}",
        "",
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


def _display_number(value: float, adapter: str) -> str:
    if adapter == "python_crap":
        return f"{value:.1f}"
    return _number(value)


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
        detail = (
            f"value {_display_number(finding.value, adapter)} exceeds "
            f"threshold {_display_number(threshold, adapter)}"
        )
        if entry is not None and not expired:
            detail += (
                " and baseline bound "
                f"{_display_number(entry.bound, adapter)}"
            )
        if expired and entry is not None and entry.expires is not None:
            detail += f" (baseline entry expired {entry.expires.isoformat()})"
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
    files = entry.extras.get("files")
    if isinstance(files, list) and files:
        return f" (files: {', '.join(files)})"
    return ""


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
                )
            )
        if domain.contains(entry.subject):
            resolved.append(entry.subject)
        else:
            unmeasured.append(entry.subject)


def evaluate(
    findings: list[Finding],
    entries: list[BaselineEntry],
    *,
    threshold: float,
    enforcement: str,
    prefix: str,
    adapter: str,
    domain: Domain,
    today: datetime.date | None = None,
) -> RatchetResult:
    today = today or datetime.date.today()
    _finite_inputs(findings, entries, threshold, prefix)
    by_subject = {entry.subject: entry for entry in entries}
    measured: dict[str, float] = {}
    results: list[FindingResult] = []
    resolved: list[str] = []
    unmeasured: list[str] = []
    (
        expired_subjects,
        empty_reason_subjects,
        failures,
        raw_failure,
        blocking_failure,
    ) = _scan_entries(entries, today, enforcement, prefix)
    exceptions = False

    for finding in findings:
        if finding.subject in measured:
            raise GateError(
                f"{prefix}: duplicate measured subject {finding.subject!r}"
            )
        measured[finding.subject] = finding.value
        entry = by_subject.get(finding.subject)
        expired = finding.subject in expired_subjects
        above_threshold = finding.value > threshold
        valid_entry = (
            entry is not None
            and not expired
            and bool(entry.reason.strip())
            and finding.value <= entry.bound
        )
        passes = (not above_threshold) or valid_entry
        if above_threshold:
            raw_failure = True
        blocking = (not passes) and enforcement == "enforced"
        blocking_failure = blocking_failure or blocking
        if entry is not None and not above_threshold:
            resolved.append(entry.subject)
        if not passes:
            failures.append(
                _format_failure(prefix, finding, entry, expired, threshold, adapter)
            )
        elif above_threshold and valid_entry:
            exceptions = True
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
        )
        if finding.subject in empty_reason_subjects:
            result.blocking = enforcement == "enforced"
            blocking_failure = blocking_failure or result.blocking
            result.error = "empty baseline reason"
            failures.append(
                f"{prefix}: baseline entry {finding.subject}: empty reason "
                f"at {finding.location}"
            )
        results.append(result)

    _record_unmeasured(
        entries,
        measured,
        empty_reason_subjects,
        expired_subjects,
        enforcement,
        threshold,
        domain,
        results,
        resolved,
        unmeasured,
    )
    for message in failures:
        print(message, file=sys.stderr)
    for subject in resolved:
        print(f"{prefix}: resolved {subject}")
    for subject in unmeasured:
        print(
            f"{prefix}: unmeasured {subject} (outside {domain.description}); kept"
        )
    return RatchetResult(
        findings=results,
        resolved=resolved,
        unmeasured=unmeasured,
        entries=entries,
        measured=measured,
        outcome="fail" if raw_failure else "pass",
        satisfied=not blocking_failure,
        exceptions=exceptions,
    )


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
        pruned.append(replace(entry, bound=min(entry.bound, value)))
    return pruned
