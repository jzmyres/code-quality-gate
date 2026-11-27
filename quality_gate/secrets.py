from __future__ import annotations

import ast
import hashlib
import io
import os
import re
import shutil
import stat
import sys
import tokenize
import warnings
import zlib
from array import array
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from functools import cached_property, partial
from itertools import batched, chain
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import public_vocab
from .json_input import load_json

_MAX_FILES_PER_INVOCATION = 24
_FINDINGS_EXIT = 3
_MAX_RECORD_BYTES = 16 << 20
_MAX_COMPRESSED_BYTES = 16 << 20
MAX_GIT_PAYLOAD_BYTES = 16 << 20
MAX_GZIP_PAYLOAD_BYTES = 32 << 20
MAX_PUBLIC_VOCABULARY_GZIP_BYTES = 16 << 20
FULL_GIT_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_PROMISOR_CONFIG = r"^(extensions\.partialclone|remote\..+\.promisor)$"
_DIGEST_WIDTH = 64
_REDACTED_ASSIGNMENT = re.compile(r'([A-Za-z0-9_.-]+"[ \t]*:[ \t]*")REDACTED"')
_PYTHON_REDACTED_ASSIGNMENT = re.compile(r"""([A-Za-z0-9_.-]+["'][ \t]*:[ \t]*(["']))REDACTED\2""")
_SHA256 = re.compile(rb"[0-9a-f]{64}")
_MARKER = "verified-provenance-position"
_GIT_FINDING_FIELDS = ("Commit", "Author", "Email", "Date", "Message")
_POSITION_FIELDS = ("StartLine", "EndLine", "StartColumn", "EndColumn")
_MATCH_FIELDS = {"RuleID", "Match", "Secret", *_POSITION_FIELDS}
_RAW_FINDING_FIELDS = {
    *_MATCH_FIELDS, "File",
    "Attributes", "Tags", "Fingerprint", "SymlinkFile", "Description", "Entropy", *_GIT_FINDING_FIELDS,
}
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
class GzipPayload:
    path: str
    compressed_sha256: str
    decoded_size: int


Payload = str | GitPayload | GzipPayload


@dataclass(frozen=True)
class Provenance:
    record: str
    pointer: tuple[str, ...]
    payload: Payload
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
    python: bool = False


def _record(data: bytes, gzip: GzipDigests | None = None, *, python: bool = False) -> _Record:
    starts = array("I", (0,))
    starts.extend(match.end() for match in re.finditer(b"\n", data))
    return _Record(data, starts, {}, gzip, python)


def _single_gzip_member(compressed: bytes, limit: int) -> bytes | None:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = inflater.decompress(compressed, limit + 1)
    except zlib.error:
        return None
    if not inflater.eof or inflater.unused_data or len(data) > limit:
        return None
    return data


def _read_gzip_bytes(path: Path) -> bytes | None:
    with path.open("rb") as stream:
        compressed = stream.read(_MAX_COMPRESSED_BYTES + 1)
    return compressed if len(compressed) <= _MAX_COMPRESSED_BYTES else None


def _read_gzip_record(path: Path) -> _Record | None:
    compressed = _read_gzip_bytes(path)
    if compressed is None:
        return None
    data = _single_gzip_member(compressed, _MAX_RECORD_BYTES)
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
    return _record(data, python=path.name.endswith(".py"))


def _tracked_record(declaration: Provenance, tracked: set[str]) -> bool:
    must_be_tracked = declaration.gzip is not None or declaration.record.endswith(".py")
    return not must_be_tracked or declaration.record in tracked


def _has_payload(payload: Payload, paths: dict[str, bool], tracked: set[str]) -> bool:
    if isinstance(payload, GitPayload):
        return True
    path = payload.path if isinstance(payload, GzipPayload) else payload
    return paths.get(path, False) and path in tracked


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


def _gzip_payload_digest(path: Path, payload: GzipPayload) -> str | None:
    if not 0 <= payload.decoded_size <= MAX_GZIP_PAYLOAD_BYTES:
        return None
    compressed = _read_gzip_bytes(path)
    if compressed is None or hashlib.sha256(compressed).hexdigest() != payload.compressed_sha256:
        return None
    data = _single_gzip_member(compressed, payload.decoded_size)
    if data is None or len(data) != payload.decoded_size:
        return None
    return hashlib.sha256(data).hexdigest()


def _payload_digest(directory: Path, payload: Payload, git: _GitPayloadReader | None) -> str | None:
    if isinstance(payload, GitPayload):
        return git.digest(payload) if git is not None else None
    if isinstance(payload, GzipPayload):
        return _gzip_payload_digest(directory / payload.path, payload)
    with (directory / payload).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _pinned_payloads(
    directory: Path, selected: Iterable[Provenance], git: _GitPayloadReader | None,
) -> Iterable[Provenance]:
    digests: dict[Payload, str | None] = {}
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


def _match_prefix(finding: dict[str, Any], *, python: bool) -> bytes | None:
    template = finding.get("Match")
    if finding.get("Secret") != "REDACTED" or not isinstance(template, str):
        return None
    if template.count("REDACTED") != 1:
        return None
    pattern = _PYTHON_REDACTED_ASSIGNMENT if python else _REDACTED_ASSIGNMENT
    match = pattern.fullmatch(template)
    return match[1].encode("ascii") if match is not None else None


def _unique_value(data: bytes, prefix: bytes, start: int, line_end: int) -> int | None:
    """Locate the sole fixed-width raw value, including overlapping candidates."""
    prefix_end = line_end - _DIGEST_WIDTH - 1
    first = None
    while (position := data.find(prefix, start, prefix_end)) != -1:
        value_start = position + len(prefix)
        if data[value_start + _DIGEST_WIDTH] == prefix[-1]:
            if first is not None:
                return None
            first = value_start
        start = position + 1
    return first


def _digest_start(record: _Record, line: int, bounds: tuple[int, int, int], prefix: bytes) -> int | None:
    """Require a unique Python match shape across the physical line."""
    start, line_end, width = bounds
    if width != len(prefix) + _DIGEST_WIDTH + 1:
        return None
    search_start = record.starts[line - 1] if record.python else start
    first = _unique_value(record.data, prefix, search_start, line_end)
    return first if first is not None and first - len(prefix) >= start else None


def _matched_digest(finding: dict[str, Any], record: _Record) -> _DigestSpan | None:
    bounds = _finding_bounds(finding, record)
    prefix = _match_prefix(finding, python=record.python)
    if bounds is None or prefix is None:
        return None
    first = _digest_start(record, finding["StartLine"], bounds, prefix)
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


def _python_tree(data: bytes) -> ast.Module | None:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        if encoding != "utf-8" or re.search(rb"\r(?!\n)", data):
            return None
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            return ast.parse(data.decode("utf-8"))
    except (SyntaxError, SyntaxWarning, ValueError, RecursionError):
        return None


def _line_source(record: _Record, node: ast.expr) -> tuple[int, bytes] | None:
    if node.lineno != node.end_lineno or node.end_col_offset is None:
        return None
    line = record.starts[node.lineno - 1]
    start = line + node.col_offset
    return start, record.data[start:line + node.end_col_offset]


def _plain_quoted_text(raw: bytes, value: str) -> bool:
    quote = raw[:1]
    return (
        quote in (b"'", b'"') and raw[-1:] == quote and b"\\" not in raw
        and raw[1:-1].decode("utf-8") == value
    )


def _literal_string(record: _Record, node: ast.expr | None) -> _DigestSpan | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    source = _line_source(record, node)
    if source is None:
        return None
    start, raw = source
    if not _plain_quoted_text(raw, node.value):
        return None
    return start + 1, start + len(raw) - 1, node.value


def _literal_dictionary(record: _Record, dictionary: ast.Dict) -> dict[str, _DigestSpan]:
    values = {}
    for key, value in zip(dictionary.keys, dictionary.values, strict=True):
        literal_key = _literal_string(record, key)
        literal_value = _literal_string(record, value)
        if literal_key is None or literal_value is None or literal_key[2] in values:
            return {}
        values[literal_key[2]] = literal_value
    return values


def _written_name(node: ast.AST) -> str | None:
    match node:
        case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
            return name
        case ast.alias(name=name, asname=alias):
            return alias or name.partition(".")[0]
        case (
            ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name)
            | ast.ExceptHandler(name=name) | ast.MatchAs(name=name) | ast.MatchStar(name=name)
            | ast.MatchMapping(rest=name)
        ):
            return name
    return None


def _exact_identifier(
    record: _Record, target: ast.Name, names: set[str], writes: Counter[str | None],
) -> bool:
    source = _line_source(record, target)
    return (
        target.id in names and writes[target.id] == 1
        and source is not None and source[1] == target.id.encode("ascii")
    )


def _dictionary_assignment(statement: ast.stmt) -> tuple[ast.Name, ast.Dict] | None:
    match statement:
        case ast.Assign(targets=[ast.Name() as target], value=ast.Dict() as dictionary):
            return target, dictionary
    return None


def _named_dictionaries(
    record: _Record, tree: ast.Module, names: set[str],
) -> dict[str, dict[str, _DigestSpan]]:
    writes = Counter(_written_name(node) for node in ast.walk(tree))
    dictionaries = {}
    if "*" in writes:
        return dictionaries
    for statement in tree.body:
        assignment = _dictionary_assignment(statement)
        if assignment is None:
            continue
        target, dictionary = assignment
        if _exact_identifier(record, target, names, writes):
            dictionaries[target.id] = _literal_dictionary(record, dictionary)
    return dictionaries


def _proven_python_spans(record: _Record, spans: Iterable[_DigestSpan]) -> Iterable[_DigestSpan]:
    tree = _python_tree(record.data)
    if tree is None:
        return
    names = {pointer[0] for pointer in chain.from_iterable(record.pointers.values())}
    dictionaries = _named_dictionaries(record, tree, names)
    for span in spans:
        if any(
            dictionaries.get(name, {}).get(key) == span for name, key in record.pointers[span[2]]
        ):
            yield span


def _raw_attachment_matches(finding: dict[str, Any], path: str) -> bool:
    attributes = finding.get("Attributes")
    return (
        isinstance(attributes, dict)
        and attributes.get("path") == path
        and attributes.get("resource") == "fs.content"
        and set(attributes) <= {"path", "resource", "confidence"}
    )


def _raw_file_match(finding: dict[str, Any], path: str) -> bool:
    return _raw_attachment_matches(finding, path) and not any(
        finding.get(field) for field in ("Tags", "ComponentSets", "SymlinkFile")
    )


def _direct_python_match(finding: dict[str, Any], path: str) -> bool:
    return (
        finding.keys() == _RAW_FINDING_FIELDS
        and finding["Tags"] == []
        and finding["SymlinkFile"] == ""
        and all(finding[field] == "" for field in _GIT_FINDING_FIELDS)
        and finding["Fingerprint"] == f"{path}:generic-api-key:{finding['StartLine']}"
    )


def _raw_provenance_match(finding: dict[str, Any], path: str, *, python: bool) -> bool:
    return (
        finding["RuleID"] == "generic-api-key" and "\ufffd" not in path and _raw_file_match(finding, path)
        and (not python or _direct_python_match(finding, path))
    )


def _candidate_span(finding: dict[str, Any], records: dict[str, _Record]) -> _DigestSpan | None:
    path = finding["File"]
    record = records.get(path)
    if record is None or not _raw_provenance_match(finding, path, python=record.python):
        return None
    return _matched_digest(finding, record)


def _proven_record_rows(record: _Record, rows: dict[_DigestSpan, list[int]]) -> Iterable[int]:
    proven = _proven_python_spans(record, rows) if record.python else _proven_spans(record, rows)
    for span in proven:
        if (not record.python and record.gzip is None) or len(rows[span]) == 1:
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


def _has_integer_coordinates(finding: dict[str, Any]) -> bool:
    return all(type(finding.get(field)) is int for field in _POSITION_FIELDS)


def _finding_metadata(finding: Any) -> bool:
    return isinstance(finding, dict) and all(
        isinstance(finding.get(field), str) and finding[field] for field in ("RuleID", "File")
    ) and _has_integer_coordinates(finding)


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


def _direct_report(paths: list[str], run_report: _ReportRun, archive_depth: int) -> list[dict[str, Any]]:
    """Replay the same captured paths without secondary decoding."""
    child = run_report(paths, f"--max-archive-depth={archive_depth}", "--max-decode-depth=0")
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


def _unique_direct_rows(
    findings: list[dict[str, Any]], candidates: set[int], run_report: _ReportRun, *, archive_depth: int,
) -> set[int]:
    if not candidates:
        return set()
    baseline = _by_coordinate(findings)
    paths = sorted({findings[index]["File"] for index in candidates})
    direct = _by_coordinate(_direct_report(paths, run_report, archive_depth))
    return {index for index in candidates if _same_unique_row(findings[index], baseline, direct)}


def _replayed_candidates(
    findings: list[dict[str, Any]], records: dict[str, _Record], candidates: set[int], run_report: _ReportRun,
) -> set[int]:
    archives = {index for index in candidates if records[findings[index]["File"]].gzip is not None}
    python = {index for index in candidates if records[findings[index]["File"]].python}
    return (
        (candidates - archives - python)
        | _unique_direct_rows(findings, archives, run_report, archive_depth=1)
        | _unique_direct_rows(findings, python, run_report, archive_depth=0)
    )


def _print_unresolved(findings: list[dict[str, Any]], verified: set[int]) -> int:
    for index, finding in enumerate(findings):
        if index in verified:
            continue
        print(
            f"path: {finding['File']!r}\nLine: {finding['StartLine']}"
            f"\nColumn: {finding['StartColumn']}\nRuleID: {finding['RuleID']}",
            file=sys.stderr,
        )
    return len(findings) - len(verified)


def _report_findings(
    child: Any, records: dict[str, _Record], run_report: _ReportRun, *,
    findings: list[dict[str, Any]] | None = None, public_verified: Iterable[int] = (),
) -> tuple[int, int]:
    if findings is None:
        findings = _report(child)
    candidates = _verified_finding_rows(findings, records)
    verified = _replayed_candidates(findings, records, candidates, run_report)
    return _print_unresolved(findings, verified.union(public_verified)), len(verified)


_VOCAB_COMPONENT_FIELDS = _MATCH_FIELDS | {"Optional"}


def _exact_publication(data: bytes | None, size: int, digest: str) -> bytes | None:
    if data is None or len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        return None
    return data


def _read_exact(path: Path, size: int, digest: str) -> bytes | None:
    with path.open("rb") as stream:
        return _exact_publication(stream.read(size + 1), size, digest)


def _published_bytes(directory: Path, proof: public_vocab.PublishedVocabulary) -> bytes | None:
    path = directory / proof.path
    if proof.compressed_size is None or proof.compressed_sha256 is None:
        return _read_exact(path, proof.published_size, proof.published_sha256)
    archive = _read_exact(path, proof.compressed_size, proof.compressed_sha256)
    if archive is None:
        return None
    raw = _single_gzip_member(archive, proof.published_size)
    return _exact_publication(raw, proof.published_size, proof.published_sha256)


def _vocabulary_report_metadata(row: dict[str, Any]) -> bool:
    return (
        row.keys() - {"ComponentSets"} == _RAW_FINDING_FIELDS
        and row["Tags"] == [] and row["SymlinkFile"] == ""
        and all(row[field] == "" for field in _GIT_FINDING_FIELDS)
    )


def _public_row(row: dict[str, Any], path: str) -> bool:
    return (
        (row["File"], row["RuleID"]) == (path, "generic-password") and "\ufffd" not in path
        and _vocabulary_report_metadata(row)
        and _raw_attachment_matches(row, path)
        and row["Fingerprint"] == f"{path}:generic-password:{row['StartLine']}"
    )


def _only_report_object(items: Any, fields: set[str]) -> dict[str, Any] | None:
    if not isinstance(items, list) or len(items) != 1:
        return None
    item, = items
    if not isinstance(item, dict) or item.keys() != fields:
        return None
    return item


def _vocabulary_components(row: dict[str, Any]) -> tuple[dict[str, Any], ...] | None:
    if "ComponentSets" not in row:
        return ()
    group = _only_report_object(row["ComponentSets"], {"components"})
    if group is None:
        return None
    component = _only_report_object(group["components"], _VOCAB_COMPONENT_FIELDS)
    if component is None:
        return None
    if component["RuleID"] != "generic-username" or component["Optional"] is not True:
        return None
    return (component,)


def _vocabulary_spans(
    record: _Record, rows: tuple[dict[str, Any], ...], keys: frozenset[str],
) -> set[public_vocab.MemberSpan]:
    spans = set()
    for row in rows:
        span = public_vocab.member_span(record.data, record.starts, row, keys)
        if span is None or span in spans:
            return set()
        spans.add(span)
    return spans


def _raw_comparable(row: dict[str, Any]) -> dict[str, Any]:
    attributes = {key: value for key, value in row["Attributes"].items() if key != "path"}
    return dict(row, File=None, Fingerprint=None, Attributes=attributes)


def _inflated_rows(
    directory: Path, path: str, data: bytes, run_report: _ReportRun,
) -> dict[_Coordinate, list[dict[str, Any]]]:
    """Replay verified bytes under the same relative name without the gzip suffix."""
    relative = path.removesuffix(".gz")
    with TemporaryDirectory(prefix="qg-public-vocabulary-", dir=directory) as work:
        destination = Path(work) / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        findings = _direct_report([relative], partial(run_report, cwd=Path(work)), archive_depth=0)
    return _by_coordinate(findings)


def _same_inflated_row(
    row: dict[str, Any], inflated: dict[_Coordinate, list[dict[str, Any]]],
) -> bool:
    relative = row["File"].removesuffix(".gz")
    replay = inflated.get((relative, *_coordinate(row)[1:]), [])
    return (
        len(replay) == 1 and _public_row(replay[0], relative)
        and _raw_comparable(row) == _raw_comparable(replay[0])
    )


_VocabularyRows = dict[int, tuple[dict[str, Any], ...]]


def _typed_vocabulary_rows(
    data: bytes, candidates: _VocabularyRows, keys: frozenset[str],
) -> _VocabularyRows:
    record = _record(data)
    spans = {index: _vocabulary_spans(record, rows, keys) for index, rows in candidates.items()}
    proven = public_vocab.proven_spans(data, set().union(*spans.values()))
    return {index: rows for index, rows in candidates.items() if spans[index] and spans[index] <= proven}


def _direct_vocabulary_rows(
    path: str, typed: _VocabularyRows, gzip: bool,
    baseline: dict[_Coordinate, list[dict[str, Any]]], run_report: _ReportRun,
) -> _VocabularyRows:
    direct = _by_coordinate(_direct_report([path], run_report, archive_depth=int(gzip)))
    return {index: rows for index, rows in typed.items() if _same_unique_row(rows[0], baseline, direct)}


def _verify_vocabulary_replay(
    directory: Path, proof: public_vocab.PublishedVocabulary, data: bytes, typed: _VocabularyRows,
    baseline: dict[_Coordinate, list[dict[str, Any]]], run_report: _ReportRun,
) -> _VocabularyRows:
    gzip = proof.compressed_size is not None
    identical = _direct_vocabulary_rows(proof.path, typed, gzip, baseline, run_report)
    if not gzip or not identical:
        return identical
    inflated = _inflated_rows(directory, proof.path, data, run_report)
    return {index: rows for index, rows in identical.items() if _same_inflated_row(rows[0], inflated)}


def _asset_rows(
    directory: Path, proof: public_vocab.PublishedVocabulary, candidates: _VocabularyRows,
    baseline: dict[_Coordinate, list[dict[str, Any]]], run_report: _ReportRun,
) -> _VocabularyRows:
    if len(candidates) > public_vocab.MAX_POINTERS:
        return {}
    data = _published_bytes(directory, proof)
    if data is None:
        return {}
    typed = _typed_vocabulary_rows(data, candidates, proof.keys)
    if not typed:
        return {}
    return _verify_vocabulary_replay(directory, proof, data, typed, baseline, run_report)


def _group_vocabulary_findings(
    findings: list[dict[str, Any]], public_paths: dict[str, public_vocab.PublishedVocabulary],
) -> dict[str, _VocabularyRows]:
    grouped: dict[str, _VocabularyRows] = defaultdict(dict)
    for index, row in enumerate(findings):
        path = row["File"]
        if path in public_paths and _public_row(row, path):
            components = _vocabulary_components(row)
            if components is not None:
                grouped[path][index] = (row, *components)
    return grouped


def _verified_vocabulary_rows(
    directory: Path, findings: list[dict[str, Any]],
    public_vocabulary: dict[str, public_vocab.PublishedVocabulary], run_report: _ReportRun,
) -> _VocabularyRows:
    if not public_vocabulary:
        return {}
    verified = {}
    baseline = _by_coordinate(findings)
    for path, candidates in _group_vocabulary_findings(findings, public_vocabulary).items():
        verified.update(_asset_rows(directory, public_vocabulary[path], candidates, baseline, run_report))
    return verified


def _vocabulary_location(rows: tuple[dict[str, Any], ...]) -> tuple[_Coordinate, ...]:
    path = rows[0]["File"]
    return tuple(
        (path, row["RuleID"], row["StartLine"], row["EndLine"], row["StartColumn"], row["EndColumn"])
        for row in rows
    )


@dataclass(frozen=True)
class VerifiedScan:
    child: Any
    unresolved: int
    verified: int
    vocabulary: tuple[tuple[_Coordinate, ...], ...] = ()


def _selected_vocabulary(
    proofs: tuple[public_vocab.PublishedVocabulary, ...], paths: dict[str, bool], tracked: set[str],
) -> dict[str, public_vocab.PublishedVocabulary]:
    return {proof.path: proof for proof in proofs if paths.get(proof.path) and proof.path in tracked}


def scan_verified(
    binary: Path, root: Path, directory: Path, selected: Iterable[str], budget: float,
    declarations: tuple[Provenance, ...], *,
    tracked: set[str], open_parent: _OpenParent, run: Callable[..., Any],
    git_run: _ReportRun | None = None,
    public_vocabulary: tuple[public_vocab.PublishedVocabulary, ...] = (),
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

    def run_report(targets: Iterable[str], *flags: str, cwd: Path = directory) -> Any:
        return run(
            [*argv, *flags, "--", *targets], cwd=cwd, env={}, budget_seconds=budget,
            capture_limit=None,
        )

    vocabulary = _selected_vocabulary(public_vocabulary, paths, tracked)
    return _scan_reports(directory, sorted(paths) or ["."], pinned, vocabulary, run_report)


def _scan_reports(
    directory: Path, paths: list[str], pinned: dict[str, list[Provenance]],
    public_vocabulary: dict[str, public_vocab.PublishedVocabulary], run_report: _ReportRun,
) -> VerifiedScan:
    unresolved = verified = 0
    with_findings = None
    vocabulary = []
    for targets in batched(paths, _MAX_FILES_PER_INVOCATION):
        child = run_report(targets)
        safe_child = replace(child, stdout=b"", stderr=b"", output_tail=b"", output_bytes=0)
        if child.execution != "completed":
            return VerifiedScan(safe_child, unresolved, verified, tuple(sorted(vocabulary)))
        findings = _report(child)
        records = _verified_records(directory, targets, pinned)
        public_rows = _verified_vocabulary_rows(directory, findings, public_vocabulary, run_report)
        batch_unresolved, batch_verified = _report_findings(
            child, records, run_report, findings=findings, public_verified=public_rows,
        )
        unresolved += batch_unresolved
        verified += batch_verified
        vocabulary.extend(_vocabulary_location(public_rows[index]) for index in sorted(public_rows))
        if child.returncode == _FINDINGS_EXIT:
            with_findings = safe_child
    return VerifiedScan(with_findings or safe_child, unresolved, verified, tuple(sorted(vocabulary)))
