from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
import zlib
from array import array
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from functools import cached_property
from itertools import batched
from pathlib import Path
from typing import Any

from .json_input import load_json

_MAX_FILES_PER_INVOCATION = 24
_FINDINGS_EXIT = 3
_MAX_RECORD_BYTES = 16 << 20
_MAX_COMPRESSED_BYTES = 16 << 20
MAX_GIT_PAYLOAD_BYTES = 16 << 20
FULL_GIT_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_PROMISOR_CONFIG = r"^(extensions\.partialclone|remote\..+\.promisor)$"
_DIGEST_WIDTH = 64
_REDACTED_ASSIGNMENT = re.compile(r'([A-Za-z0-9_.-]+"[ \t]*:[ \t]*")REDACTED"')
_SHA256 = re.compile(rb"[0-9a-f]{64}")
_MARKER = "verified-provenance-position"
_OpenParent = Callable[[Path, str], int]
_DigestSpan = tuple[int, int, str]
_Coordinate = tuple[str, str, int, int, int, int]
_ReportRun = Callable[..., Any]


@dataclass(frozen=True)
class GzipDigests:
    compressed: str
    decoded: str


@dataclass(frozen=True)
class GitPayload:
    path: str
    commit: str
    blob: str
    size: int


@dataclass(frozen=True)
class Provenance:
    record: str
    pointer: tuple[str, ...]
    payload: str | GitPayload
    payload_sha256: str
    gzip: GzipDigests | None = None


def _copy_regular(parent: int, name: str, destination: Path, relative: str) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"{relative}: expected a regular file")
        with destination.open("wb") as target:
            shutil.copyfileobj(source, target)


def _copy_input(root: Path, destination: Path, relative: str, open_parent: _OpenParent) -> bool | None:
    """Capture a file without following links. Return whether the source was regular."""
    parent = open_parent(root, relative)
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


def _snapshot(
    root: Path, directory: Path, selected: Iterable[str], open_parent: _OpenParent,
) -> dict[str, bool]:
    paths = {}
    for relative in selected:
        parent = (root / relative).parent
        if parent.resolve() != parent:
            continue
        regular = _copy_input(root, directory / relative, relative, open_parent)
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
    *, open_parent: _OpenParent, run: Callable[..., Any],
) -> Any:
    paths = sorted(_snapshot(root, directory, selected, open_parent))
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
    starts: Sequence[int]
    pointers: dict[str, list[tuple[str, ...]]]
    gzip: GzipDigests | None = None


def _record(data: bytes, gzip: GzipDigests | None = None) -> _Record:
    starts = array("I", (0,))
    starts.extend(match.end() for match in re.finditer(b"\n", data))
    return _Record(data, starts, {}, gzip)


def _single_gzip_member(compressed: bytes) -> bytes | None:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = inflater.decompress(compressed, _MAX_RECORD_BYTES + 1)
    except zlib.error:
        return None
    if not inflater.eof or inflater.unused_data or len(data) > _MAX_RECORD_BYTES:
        return None
    return data


def _read_gzip_record(path: Path) -> _Record | None:
    with path.open("rb") as stream:
        compressed = stream.read(_MAX_COMPRESSED_BYTES + 1)
    if len(compressed) > _MAX_COMPRESSED_BYTES:
        return None
    data = _single_gzip_member(compressed)
    if data is None:
        return None
    digests = GzipDigests(hashlib.sha256(compressed).hexdigest(), hashlib.sha256(data).hexdigest())
    return _record(data, digests)


def _read_record(path: Path) -> _Record | None:
    if path.name.endswith(".json.gz"):
        return _read_gzip_record(path)
    with path.open("rb") as stream:
        data = stream.read(_MAX_RECORD_BYTES + 1)
    if len(data) > _MAX_RECORD_BYTES:
        return None
    return _record(data)


def _tracked_record(declaration: Provenance, tracked: set[str]) -> bool:
    return declaration.gzip is None or declaration.record in tracked


def _has_payload(payload: str | GitPayload, paths: dict[str, bool], tracked: set[str]) -> bool:
    return isinstance(payload, GitPayload) or (paths.get(payload, False) and payload in tracked)


def _selected_provenance(
    paths: dict[str, bool], tracked: set[str],
    declarations: tuple[Provenance, ...],
) -> Iterable[Provenance]:
    for declaration in declarations:
        if not paths.get(declaration.record) or not _tracked_record(declaration, tracked):
            continue
        if _has_payload(declaration.payload, paths, tracked):
            yield declaration


def _exact_tree_entry(entry: bytes, payload: GitPayload) -> bool:
    header, _, name = entry.partition(b"\t")
    mode, _, identity = header.partition(b" ")
    return (
        name == os.fsencode(payload.path) + b"\0"
        and mode in (b"100644", b"100755")
        and identity.split() == [b"blob", payload.blob.encode("ascii"), str(payload.size).encode("ascii")]
    )


def _blob_digest(data: bytes, payload: GitPayload) -> str | None:
    if len(data) != payload.size:
        return None
    algorithm = "sha1" if len(payload.blob) == 40 else "sha256"
    object_hash = hashlib.new(algorithm, usedforsecurity=False)
    object_hash.update(f"blob {payload.size}\0".encode("ascii"))
    object_hash.update(data)
    return hashlib.sha256(data).hexdigest() if object_hash.hexdigest() == payload.blob else None


class _GitPayloadReader:
    def __init__(self, command: _ReportRun) -> None:
        self.command = command
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
            GIT_GRAFT_FILE=os.devnull, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="",
        )

    def _read(self, *args: str, limit: int = 8192, status: int = 0) -> bytes | None:
        child = self.command(*args, env=self.env, capture_limit=limit)
        if (child is None or child.execution != "completed" or child.returncode != status
                or child.output_truncated or child.stderr):
            return None
        return child.stdout

    @cached_property
    def head(self) -> str | None:
        """Resolve HEAD without allowing older Git to attempt a promisor lookup."""
        if self._read("config", "--get-regexp", _PROMISOR_CONFIG, status=1) != b"":
            return None
        return self._commit("HEAD")

    def _commit(self, revision: str) -> str | None:
        data = self._read("rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}")
        if data is None:
            return None
        value = data.decode("ascii", "replace").removesuffix("\n")
        return value if FULL_GIT_OBJECT.fullmatch(value) else None

    def _reachable_commit(self, commit: str) -> bool:
        head = self.head
        return (
            head is not None
            and len(head) == len(commit)
            and self._commit(commit) == commit
            and self._read("merge-base", "--is-ancestor", commit, head) == b""
        )

    def digest(self, payload: GitPayload) -> str | None:
        if not 0 <= payload.size <= MAX_GIT_PAYLOAD_BYTES or not self._reachable_commit(payload.commit):
            return None
        entry = self._read(
            "--literal-pathspecs", "ls-tree", "-z", "-l", "--full-tree",
            payload.commit, "--", payload.path,
        )
        if entry is None or not _exact_tree_entry(entry, payload):
            return None
        data = self._read("cat-file", "blob", payload.blob, limit=payload.size)
        return None if data is None else _blob_digest(data, payload)


def _payload_digest(directory: Path, payload: str | GitPayload, git: _GitPayloadReader | None) -> str | None:
    if isinstance(payload, GitPayload):
        return git.digest(payload) if git is not None else None
    with (directory / payload).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _pinned_payloads(
    directory: Path, selected: Iterable[Provenance], git: _GitPayloadReader | None,
) -> Iterable[Provenance]:
    digests: dict[str | GitPayload, str | None] = {}
    for declaration in selected:
        payload = declaration.payload
        if payload not in digests:
            digests[payload] = _payload_digest(directory, payload, git)
        if digests[payload] == declaration.payload_sha256:
            yield declaration


def _verified_records(
    directory: Path, paths: Iterable[str], pinned: dict[str, list[Provenance]],
) -> dict[str, _Record]:
    records = {}
    for path in paths:
        if path not in pinned:
            continue
        record = _read_record(directory / path)
        if record is None:
            continue
        for declaration in pinned[path]:
            if record.gzip == declaration.gzip:
                record.pointers.setdefault(declaration.payload_sha256, []).append(declaration.pointer)
        records[path] = record
    return records


def _finding_bounds(finding: dict[str, Any], record: _Record) -> tuple[int, int, int] | None:
    """Betterleaks v1.10.1 can start mid-line, making its start column a lower bound."""
    line = finding["StartLine"]
    start, end = finding["StartColumn"] - 1, finding["EndColumn"]
    if not (line == finding["EndLine"] and 1 <= line <= len(record.starts) and 0 <= start < end):
        return None
    line_start = record.starts[line - 1]
    line_end = record.starts[line] - 1 if line < len(record.starts) else len(record.data)
    if line_start + end > line_end:
        return None
    return line_start + start, line_end, end - start


def _match_prefix(finding: dict[str, Any]) -> bytes | None:
    template = finding.get("Match")
    if finding.get("Secret") != "REDACTED" or not isinstance(template, str):
        return None
    if template.count("REDACTED") != 1:
        return None
    match = _REDACTED_ASSIGNMENT.fullmatch(template)
    return match[1].encode("ascii") if match is not None else None


def _unique_value(data: bytes, prefix: bytes, start: int, line_end: int) -> int | None:
    """Locate the sole fixed-width raw value, including overlapping candidates."""
    prefix_end = line_end - _DIGEST_WIDTH - 1
    first = None
    while (position := data.find(prefix, start, prefix_end)) != -1:
        value_start = position + len(prefix)
        if data[value_start + _DIGEST_WIDTH] == ord('"'):
            if first is not None:
                return None
            first = value_start
        start = position + 1
    return first


def _matched_digest(finding: dict[str, Any], record: _Record) -> tuple[int, int, str] | None:
    bounds = _finding_bounds(finding, record)
    prefix = _match_prefix(finding)
    if bounds is None or prefix is None:
        return None
    start, line_end, width = bounds
    if width != len(prefix) + _DIGEST_WIDTH + 1:
        return None
    first = _unique_value(record.data, prefix, start, line_end)
    if first is None:
        return None
    last = first + _DIGEST_WIDTH
    digest = record.data[first:last]
    if not _SHA256.fullmatch(digest):
        return None
    return first, last, digest.decode("ascii")


def _marked_record(
    data: bytes, spans: Iterable[_DigestSpan],
) -> tuple[bytearray, dict[_DigestSpan, str]]:
    """Give each candidate span its own fixed-width marker.

    A matched digest sits between unescaped quotes, so distinct spans cannot
    overlap in a valid document. The markers keep all other offsets intact.
    """
    marked_bytes = bytearray(data)
    markers = {}
    for span in spans:
        start, end, _ = span
        marker = f"{_MARKER}-{start}".ljust(_DIGEST_WIDTH, "-")
        marked_bytes[start:end] = marker.encode("ascii")
        markers[span] = marker
    return marked_bytes, markers


def _proven_spans(record: _Record, spans: Iterable[_DigestSpan]) -> Iterable[_DigestSpan]:
    """Bind each candidate span to the declared scalar in both record parses."""
    marked_bytes, markers = _marked_record(record.data, spans)
    try:
        original = load_json(record.data.decode("utf-8"))
        marked = load_json(marked_bytes.decode("utf-8"))
    except (ValueError, RecursionError):
        return
    for span, marker in markers.items():
        digest = span[2]
        if any(
            _pointer_value(original, pointer) == digest and _pointer_value(marked, pointer) == marker
            for pointer in record.pointers[digest]
        ):
            yield span


def _raw_file_match(finding: dict[str, Any], path: str) -> bool:
    attributes = finding.get("Attributes")
    return (
        isinstance(attributes, dict)
        and attributes.get("path") == path
        and attributes.get("resource") == "fs.content"
        and set(attributes) <= {"path", "resource", "confidence"}
        and not any(finding.get(field) for field in ("Tags", "ComponentSets", "SymlinkFile"))
    )


def _candidate_span(finding: dict[str, Any], records: dict[str, _Record]) -> _DigestSpan | None:
    path = finding["File"]
    if finding["RuleID"] != "generic-api-key" or "\ufffd" in path or not _raw_file_match(finding, path):
        return None
    record = records.get(path)
    if record is None:
        return None
    return _matched_digest(finding, record)


def _proven_record_rows(record: _Record, rows: dict[_DigestSpan, list[int]]) -> Iterable[int]:
    for span in _proven_spans(record, rows):
        if record.gzip is None or len(rows[span]) == 1:
            yield from rows[span]


def _verified_finding_rows(findings: list[dict[str, Any]], records: dict[str, _Record]) -> set[int]:
    candidates: dict[str, dict[_DigestSpan, list[int]]] = {}
    for index, finding in enumerate(findings):
        span = _candidate_span(finding, records)
        path = finding["File"]
        if span is not None and span[2] in records[path].pointers:
            candidates.setdefault(path, {}).setdefault(span, []).append(index)
    return {index for path, rows in candidates.items() for index in _proven_record_rows(records[path], rows)}


def _decode_report(child: Any) -> list[Any]:
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


def _report(child: Any) -> list[dict[str, Any]]:
    if child.returncode not in (0, _FINDINGS_EXIT):
        raise ValueError(f"Betterleaks scan failed with exit {child.returncode}")
    findings = _decode_report(child)
    if not all(_finding_metadata(finding) for finding in findings):
        raise ValueError("Betterleaks report is missing finding metadata or coordinates")
    return findings


def _coordinate(finding: dict[str, Any]) -> _Coordinate:
    return (
        finding["File"], finding["RuleID"], finding["StartLine"], finding["EndLine"],
        finding["StartColumn"], finding["EndColumn"],
    )


def _by_coordinate(findings: list[dict[str, Any]]) -> dict[_Coordinate, list[dict[str, Any]]]:
    coordinates = defaultdict(list)
    for finding in findings:
        coordinates[_coordinate(finding)].append(finding)
    return coordinates


def _direct_gzip_report(paths: list[str], run_report: _ReportRun) -> list[dict[str, Any]]:
    """Replay the same archive paths through one decompression layer and no codecs."""
    child = run_report(paths, "--max-archive-depth=1", "--max-decode-depth=0")
    if child.execution != "completed":
        return []
    try:
        return _report(child)
    except ValueError:
        return []


def _same_unique_row(
    row: dict[str, Any], baseline: dict[_Coordinate, list[dict[str, Any]]],
    direct: dict[_Coordinate, list[dict[str, Any]]],
) -> bool:
    key = _coordinate(row)
    return baseline[key] == direct.get(key) == [row]


def _unique_direct_gzip_rows(
    findings: list[dict[str, Any]], candidates: set[int], run_report: _ReportRun,
) -> set[int]:
    if not candidates:
        return set()
    baseline = _by_coordinate(findings)
    paths = sorted({findings[index]["File"] for index in candidates})
    direct = _by_coordinate(_direct_gzip_report(paths, run_report))
    return {index for index in candidates if _same_unique_row(findings[index], baseline, direct)}


def _report_findings(child: Any, records: dict[str, _Record], run_report: _ReportRun) -> tuple[int, int]:
    findings = _report(child)
    candidates = _verified_finding_rows(findings, records)
    archives = {index for index in candidates if records[findings[index]["File"]].gzip is not None}
    verified = (candidates - archives) | _unique_direct_gzip_rows(findings, archives, run_report)
    for index, finding in enumerate(findings):
        if index in verified:
            continue
        print(
            f"path: {finding['File']!r}\nLine: {finding['StartLine']}"
            f"\nColumn: {finding['StartColumn']}\nRuleID: {finding['RuleID']}",
            file=sys.stderr,
        )
    return len(findings) - len(verified), len(verified)


@dataclass(frozen=True)
class VerifiedScan:
    child: Any
    unresolved: int
    verified: int


def scan_verified(
    binary: Path, root: Path, directory: Path, selected: Iterable[str], budget: float,
    declarations: tuple[Provenance, ...], *,
    tracked: set[str], open_parent: _OpenParent, run: Callable[..., Any],
    git_run: _ReportRun | None = None,
) -> VerifiedScan:
    paths = _snapshot(root, directory, selected, open_parent)
    candidates = _selected_provenance(paths, tracked, declarations)
    pinned = defaultdict(list)
    git = _GitPayloadReader(git_run) if git_run is not None else None
    for declaration in _pinned_payloads(directory, candidates, git):
        pinned[declaration.record].append(declaration)
    argv = [
        *_scanner_argv(binary), f"--exit-code={_FINDINGS_EXIT}",
        "--report-format=json", "--report-path=-",
    ]

    def run_report(targets: Iterable[str], *flags: str) -> Any:
        return run(
            [*argv, *flags, "--", *targets], cwd=directory, env={}, budget_seconds=budget,
            capture_limit=None,
        )

    return _scan_reports(directory, sorted(paths) or ["."], pinned, run_report)


def _scan_reports(
    directory: Path, paths: list[str], pinned: dict[str, list[Provenance]], run_report: _ReportRun,
) -> VerifiedScan:
    unresolved = verified = 0
    with_findings = None
    for targets in batched(paths, _MAX_FILES_PER_INVOCATION):
        child = run_report(targets)
        safe_child = replace(child, stdout=b"", stderr=b"", output_tail=b"", output_bytes=0)
        if child.execution != "completed":
            return VerifiedScan(safe_child, unresolved, verified)
        records = _verified_records(directory, targets, pinned)
        batch_unresolved, batch_verified = _report_findings(child, records, run_report)
        unresolved += batch_unresolved
        verified += batch_verified
        if child.returncode == _FINDINGS_EXIT:
            with_findings = safe_child
    return VerifiedScan(with_findings or safe_child, unresolved, verified)
