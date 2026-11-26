from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from itertools import batched
from pathlib import Path
from typing import Any

from .files import GitFile, _parent_fd
from .json_input import load_json
from .policy import _check_keys, _config_error, _string, _unique, _validate_exact_path
from .runner import RunResult

_MAX_FILES_PER_INVOCATION = 24
_FINDINGS_EXIT = 3
_MAX_RECORD_BYTES = 16 << 20
_SHA256 = re.compile(r"[0-9a-f]{64}")
# Betterleaks v1.10.1 locates the entire regex match, including the key suffix.
_ASSIGNMENT = re.compile(rb'[A-Za-z0-9_.-]+"[ \t]*:[ \t]*"([0-9a-f]{64})"')
_MARKER = "verified-provenance-position"
_PROVENANCE_FIELDS = ("record", "pointer", "payload", "payload_sha256")


@dataclass(frozen=True)
class Provenance:
    record: str
    pointer: tuple[str, ...]
    payload: str
    payload_sha256: str


def _read_pointer(pointer: str, path: Path, where: str) -> tuple[str, ...]:
    if not pointer.startswith("/") or re.search(r"~(?:[^01]|$)", pointer):
        raise _config_error(path, where, "a non-root JSON Pointer", "invalid syntax")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:])


def _parse_provenance(row: Any, path: Path, where: str) -> Provenance:
    if not isinstance(row, dict):
        raise _config_error(path, where, "a table", type(row).__name__)
    _check_keys(row, _PROVENANCE_FIELDS, path, where)
    record, pointer, payload, digest = (
        _string(row, field, path, f"{where}.{field}") for field in _PROVENANCE_FIELDS
    )
    _validate_exact_path(path, f"{where}.record", record)
    _validate_exact_path(path, f"{where}.payload", payload)
    if not record.endswith(".json") or record == payload:
        raise _config_error(path, where, "a .json record and a separate payload", "invalid paths")
    if not _SHA256.fullmatch(digest):
        raise _config_error(path, f"{where}.payload_sha256", "64 lowercase hex digits", "invalid value")
    return Provenance(record, _read_pointer(pointer, path, f"{where}.pointer"), payload, digest)


def provenance_spec(raw: dict[str, Any], path: Path, key: str) -> tuple[Provenance, ...]:
    name = f"{key}.sha256_provenance"
    rows = raw.get("sha256_provenance", [])
    if not isinstance(rows, list):
        raise _config_error(path, name, "an array of tables", type(rows).__name__)
    declarations = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for index, row in enumerate(rows):
        where = f"{name}[{index}]"
        declaration = _parse_provenance(row, path, where)
        _unique(
            seen, (declaration.record, declaration.pointer), path, where,
            "a unique record and pointer", "duplicate", _config_error,
        )
        declarations.append(declaration)
    return tuple(declarations)


def _copy_regular(parent: int, name: str, destination: Path, relative: str) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"{relative}: expected a regular file")
        with destination.open("wb") as target:
            shutil.copyfileobj(source, target)


def _copy_input(root: Path, destination: Path, relative: str) -> bool | None:
    """Capture a file without following links. Return whether the source was regular."""
    parent = _parent_fd(root, relative)
    name = Path(relative).name
    try:
        mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            return None
        destination.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(mode):
            destination.write_bytes(os.fsencode(os.readlink(name, dir_fd=parent)))
            return False
        if not stat.S_ISREG(mode):
            raise ValueError(f"{relative}: expected a regular file or symlink")
        _copy_regular(parent, name, destination, relative)
        return True
    finally:
        os.close(parent)


def _snapshot(root: Path, directory: Path, selected: Iterable[str]) -> dict[str, bool]:
    paths = {}
    for relative in selected:
        parent = (root / relative).parent
        if parent.resolve() != parent:
            continue
        regular = _copy_input(root, directory / relative, relative)
        if regular is not None:
            paths[relative] = regular
    return paths


def _scanner_argv(binary: Path) -> list[str]:
    return [
        str(binary), "dir", "--no-banner", "--no-color", "--redact=100",
        "--validation=false", "--unsafe-auto-load-config=false",
        "--gitleaks-ignore-path=/dev/null", "--ignore-gitleaks-allow",
    ]


def scan(
    binary: Path, root: Path, directory: Path, selected: Iterable[str], budget: float,
    *, run: Callable[..., Any],
) -> Any:
    paths = sorted(_snapshot(root, directory, selected))
    argv = [*_scanner_argv(binary), "--verbose", "--legacy-print", "--"]
    failed = None
    for targets in batched(paths or ["."], _MAX_FILES_PER_INVOCATION):
        child = run(
            [*argv, *targets], cwd=directory, env={},
            budget_seconds=budget, capture_limit=None,
        )
        sys.stderr.buffer.write(child.stdout)
        sys.stderr.buffer.write(child.stderr)
        sys.stderr.buffer.flush()
        if child.execution != "completed":
            return child
        if child.returncode:
            failed = child
    return failed or child


def _pointer_value(value: Any, pointer: tuple[str, ...]) -> Any:
    for part in pointer:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]{0,8}", part):
            index = int(part)
            value = value[index] if index < len(value) else None
        else:
            return None
    return value


@dataclass
class _Record:
    data: bytes
    starts: tuple[int, ...]
    pointers: dict[str, list[tuple[str, ...]]]


def _read_record(path: Path) -> _Record | None:
    with path.open("rb") as stream:
        data = stream.read(_MAX_RECORD_BYTES + 1)
    if len(data) > _MAX_RECORD_BYTES:
        return None
    return _Record(data, (0, *(match.end() for match in re.finditer(b"\n", data))), {})


def _selected_provenance(
    paths: dict[str, bool], tracked: set[str],
    declarations: tuple[Provenance, ...],
) -> Iterable[Provenance]:
    for declaration in declarations:
        if (
            paths.get(declaration.record) and paths.get(declaration.payload)
            and declaration.payload in tracked
        ):
            yield declaration


def _pinned_payloads(directory: Path, selected: Iterable[Provenance]) -> Iterable[Provenance]:
    digests: dict[str, str] = {}
    for declaration in selected:
        if declaration.payload not in digests:
            with (directory / declaration.payload).open("rb") as stream:
                digests[declaration.payload] = hashlib.file_digest(stream, "sha256").hexdigest()
        if digests[declaration.payload] == declaration.payload_sha256:
            yield declaration


def _verified_records(directory: Path, pinned: Iterable[Provenance]) -> dict[str, _Record]:
    records: dict[str, _Record | None] = {}
    for declaration in pinned:
        if declaration.record not in records:
            records[declaration.record] = _read_record(directory / declaration.record)
        record = records[declaration.record]
        if record is not None:
            record.pointers.setdefault(declaration.payload_sha256, []).append(declaration.pointer)
    return {path: record for path, record in records.items() if record is not None}


def _matched_span(finding: dict[str, Any], record: _Record) -> tuple[int, int] | None:
    line = finding["StartLine"]
    start, end = finding["StartColumn"] - 1, finding["EndColumn"]
    if not (line == finding["EndLine"] and 1 <= line <= len(record.starts) and 0 <= start < end):
        return None
    line_start = record.starts[line - 1]
    line_end = record.starts[line] - 1 if line < len(record.starts) else len(record.data)
    if line_start + end > line_end:
        return None
    return line_start + start, line_start + end


def _matched_digest(
    finding: dict[str, Any], data: bytes, span: tuple[int, int] | None,
) -> tuple[int, int, str] | None:
    if span is None:
        return None
    start, end = span
    raw = data[start:end]
    assignment = _ASSIGNMENT.fullmatch(raw)
    if assignment is None:
        return None
    first, last = assignment.span(1)
    expected = (raw[:first] + b"REDACTED" + raw[last:]).decode("ascii")
    if finding.get("Secret") != "REDACTED" or finding.get("Match") != expected:
        return None
    return start + first, start + last, assignment[1].decode("ascii")


def _proves_pointer(record: _Record, start: int, end: int, digest: str) -> bool:
    pointers = record.pointers.get(digest)
    if not pointers:
        return False
    try:
        original = load_json(record.data.decode("utf-8"))
        # Prove which pointer refers to these bytes even when the same digest occurs elsewhere.
        marked_bytes = record.data[:start] + _MARKER.encode("ascii") + record.data[end:]
        marked = load_json(marked_bytes.decode("utf-8"))
    except (ValueError, RecursionError):
        return False
    return any(
        _pointer_value(original, pointer) == digest
        and _pointer_value(marked, pointer) == _MARKER
        for pointer in pointers
    )


def _raw_file_match(finding: dict[str, Any], path: str) -> bool:
    attributes = finding.get("Attributes")
    return (
        isinstance(attributes, dict)
        and attributes.get("path") == path
        and attributes.get("resource") == "fs.content"
        and set(attributes) <= {"path", "resource", "confidence"}
        and not any(finding.get(field) for field in ("Tags", "ComponentSets", "SymlinkFile"))
    )


def _eligible_finding(finding: dict[str, Any], records: dict[str, _Record]) -> bool:
    path = finding["File"]
    if finding["RuleID"] != "generic-api-key" or "\ufffd" in path or not _raw_file_match(finding, path):
        return False
    record = records.get(path)
    if record is None:
        return False
    digest = _matched_digest(finding, record.data, _matched_span(finding, record))
    return digest is not None and _proves_pointer(record, *digest)


def _decode_report(child: RunResult) -> list[Any]:
    if child.output_truncated:
        raise ValueError("Betterleaks report was truncated")
    try:
        findings = load_json(child.stdout.decode("utf-8"))
    except (ValueError, RecursionError):
        raise ValueError("Betterleaks did not produce a valid JSON report") from None
    if not isinstance(findings, list) or bool(findings) != (child.returncode == _FINDINGS_EXIT):
        raise ValueError("Betterleaks report and exit status disagree")
    return findings


def _finding_metadata(finding: Any) -> bool:
    return isinstance(finding, dict) and all(
        isinstance(finding.get(field), str) and finding[field] for field in ("RuleID", "File")
    ) and all(
        type(finding.get(field)) is int for field in ("StartLine", "EndLine", "StartColumn", "EndColumn")
    )


def _report(child: RunResult) -> list[dict[str, Any]]:
    if child.returncode not in (0, _FINDINGS_EXIT):
        raise ValueError(f"Betterleaks scan failed with exit {child.returncode}")
    findings = _decode_report(child)
    if not all(_finding_metadata(finding) for finding in findings):
        raise ValueError("Betterleaks report is missing finding metadata or coordinates")
    return findings


def _report_findings(child: RunResult, records: dict[str, _Record]) -> tuple[int, int]:
    findings = _report(child)
    verified = 0
    for finding in findings:
        if _eligible_finding(finding, records):
            verified += 1
            continue
        print(
            f"path: {finding['File']!r}\nLine: {finding['StartLine']}"
            f"\nColumn: {finding['StartColumn']}\nRuleID: {finding['RuleID']}",
            file=sys.stderr,
        )
    return len(findings) - verified, verified


@dataclass(frozen=True)
class VerifiedScan:
    child: RunResult
    unresolved: int
    verified: int


def scan_verified(
    binary: Path, root: Path, directory: Path, entries: list[GitFile], budget: float,
    declarations: tuple[Provenance, ...], *, run: Callable[..., RunResult],
) -> VerifiedScan:
    paths = _snapshot(root, directory, (entry.path for entry in entries))
    tracked = {entry.path for entry in entries if entry.mode in ("100644", "100755")}
    selected = _selected_provenance(paths, tracked, declarations)
    records = _verified_records(directory, _pinned_payloads(directory, selected))
    argv = [
        *_scanner_argv(binary), f"--exit-code={_FINDINGS_EXIT}",
        "--report-format=json", "--report-path=-", "--",
    ]
    return _scan_reports(argv, directory, sorted(paths) or ["."], records, budget, run)


def _scan_reports(
    argv: list[str], directory: Path, paths: list[str], records: dict[str, _Record], budget: float,
    run: Callable[..., RunResult],
) -> VerifiedScan:
    unresolved = verified = 0
    with_findings = None
    for targets in batched(paths, _MAX_FILES_PER_INVOCATION):
        child = run([*argv, *targets], cwd=directory, env={}, budget_seconds=budget, capture_limit=None)
        safe_child = replace(child, stdout=b"", stderr=b"", output_tail=b"", output_bytes=0)
        if child.execution != "completed":
            return VerifiedScan(safe_child, unresolved, verified)
        batch_unresolved, batch_verified = _report_findings(child, records)
        unresolved += batch_unresolved
        verified += batch_verified
        if child.returncode == _FINDINGS_EXIT:
            with_findings = safe_child
    return VerifiedScan(with_findings or safe_child, unresolved, verified)
