"""Prove a typed scanner occurrence from a trusted public hardware catalogue."""
from __future__ import annotations

import ast
import hashlib
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache, partial
from pathlib import Path
from typing import Any

from . import secrets
from .json_input import load_json

_Span = tuple[int, int]


@dataclass(frozen=True)
class Catalogue:
    payload: secrets.GitPayload
    sha256: str
    literal_span: _Span


@dataclass(frozen=True)
class Declaration:
    record: str
    pointer: tuple[str, ...]
    match_span: _Span
    decoded_sha256: str
    catalogue: Catalogue
    compressed_sha256: str | None = None


@dataclass(frozen=True)
class PythonDeclaration:
    record: str
    role: str
    identifier: str
    match_span: _Span
    source_sha256: str
    catalogue: Catalogue


ModelDeclaration = Declaration | PythonDeclaration


@dataclass(frozen=True)
class _Proof:
    declaration: ModelDeclaration
    label: str


@dataclass(frozen=True)
class _Record:
    source: secrets._Record
    decoded_sha256: str
    original: Any


def _literal_at(data: bytes, span: _Span) -> str | None:
    tree = secrets._python_tree(data)
    if tree is None:
        return None
    source = secrets._record(data)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        literal = secrets._literal_string(source, node)
        if literal is not None and literal[:2] == span:
            return literal[2]
    return None


def _catalogue_label(read_blob: secrets._ReadGitBlob, catalogue: Catalogue) -> str | None:
    checked = read_blob(catalogue.payload)
    if checked is None or checked[1] != catalogue.sha256:
        return None
    return _literal_at(checked[0], catalogue.literal_span)


def _selected(declaration: ModelDeclaration, paths: dict[str, bool], tracked: set[str]) -> bool:
    path = declaration.record
    if not paths.get(path) or path not in tracked or path == declaration.catalogue.payload.path:
        return False
    if isinstance(declaration, PythonDeclaration):
        return path.endswith(".py")
    return path.endswith((".json", ".json.gz")) and (
        path.endswith(".json.gz") == (declaration.compressed_sha256 is not None)
    )


def prepare(
    declarations: tuple[ModelDeclaration, ...], paths: dict[str, bool], tracked: set[str],
    read_blob: secrets._ReadGitBlob,
) -> dict[str, tuple[_Proof, ...]]:
    """Read catalogue bytes only through the authenticated Git blob reader."""
    label_at = cache(partial(_catalogue_label, read_blob))
    proofs = defaultdict(list)
    for declaration in declarations:
        if not _selected(declaration, paths, tracked):
            continue
        label = label_at(declaration.catalogue)
        if label:
            proofs[declaration.record].append(_Proof(declaration, label))
    return {path: tuple(rows) for path, rows in proofs.items()}


def _load_record(path: Path) -> _Record | None:
    source = secrets._read_record(path)
    if source is None:
        return None
    digest = source.gzip.decoded if source.gzip else hashlib.sha256(source.data).hexdigest()
    if source.python:
        tree = secrets._python_tree(source.data)
        return _Record(source, digest, tree) if tree is not None else None
    try:
        original = load_json(source.data.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return _Record(source, digest, original)


def _pinned_bytes(proof: Declaration, record: _Record) -> bool:
    archive = record.source.gzip
    compressed = archive.compressed if archive else None
    return proof.decoded_sha256 == record.decoded_sha256 and proof.compressed_sha256 == compressed


def _raw_row(row: dict[str, Any], path: str) -> bool:
    return (
        secrets._raw_provenance_match(row, path, python=False)
        and secrets._direct_generic_match(row, path)
        and row["Attributes"].get("confidence") in ("low", "medium", "high")
    )


def _value_span(row: dict[str, Any], record: secrets._Record, match: _Span) -> _Span | None:
    bounds = secrets._finding_bounds(row, record)
    prefix = secrets._match_prefix(row, python=False)
    if bounds is None or prefix is None:
        return None
    start, line_end, width = bounds
    value_width = width - len(prefix) - 1
    if match != (start, start + width) or value_width <= 0:
        return None
    line_start = record.starts[row["StartLine"] - 1]
    value_start = start + len(prefix)
    if secrets._unique_value(record.data, prefix, line_start, line_end, value_width) != value_start:
        return None
    return value_start, start + width - 1


def _bind_pointer(record: _Record, span: _Span, pointer: tuple[str, ...], label: str) -> bool:
    """Bind the pointer by changing just the matched span to a different string of the same byte width."""
    start, end = span
    data = record.source.data
    if data[start:end] != label.encode("utf-8") or secrets._pointer_value(record.original, pointer) != label:
        return False
    marker = (b"!" if data[start:start + 1] == b"~" else b"~") * (end - start)
    try:
        marked = load_json((data[:start] + marker + data[end:]).decode("utf-8"))
    except (ValueError, RecursionError):
        return False
    return secrets._pointer_value(marked, pointer) == marker.decode("ascii")


def _python_match(
    row: dict[str, Any], source: secrets._Record, match: _Span, literal: secrets._DigestSpan,
) -> bool:
    """Compare the whole finding with the spelling of a bound Python literal."""
    bounds = secrets._finding_bounds(row, source)
    if bounds is None or row.get("Secret") != "REDACTED":
        return False
    start, line_end, width = bounds
    first, end, _ = literal
    if match != (start, start + width) or match[1] != end + 1:
        return False
    prefix = source.data[start:first]
    redacted = prefix + b"REDACTED" + source.data[end:match[1]]
    line_start = source.starts[row["StartLine"] - 1]
    return (
        row.get("Match") == redacted.decode("ascii")
        and secrets._unique_value(source.data, prefix, line_start, line_end, end - first) == first
    )


def _unique_keyword(call: ast.Call, identifier: str) -> ast.keyword | None:
    matches = [argument for argument in call.keywords if argument.arg == identifier]
    return matches[0] if len(matches) == 1 else None


def _python_operands(
    tree: ast.Module, declaration: PythonDeclaration,
) -> Iterator[tuple[ast.keyword | ast.Attribute, ast.expr]]:
    for node in ast.walk(tree):
        match declaration.role, node:
            case "keyword", ast.Call() as call:
                argument = _unique_keyword(call, declaration.identifier)
                if argument is not None:
                    yield argument, argument.value
            case "attribute_equality", ast.Compare(
                left=ast.Attribute() as target, ops=[ast.Eq()], comparators=[value],
            ):
                yield target, value


def _python_anchor(
    source: secrets._Record, operand: ast.keyword | ast.Attribute, identifier: bytes,
) -> int | None:
    if isinstance(operand, ast.keyword):
        return source.starts[operand.lineno - 1] + operand.col_offset
    position = secrets._line_source(source, operand)
    if position is None:
        return None
    start, raw = position
    return start + len(raw) - len(identifier) if raw.endswith(b"." + identifier) else None


def _python_site(
    source: secrets._Record, operand: ast.keyword | ast.Attribute, literal: secrets._DigestSpan,
    declaration: PythonDeclaration,
) -> bool:
    identifier = declaration.identifier.encode("utf-8")
    start = _python_anchor(source, operand, identifier)
    if start is None:
        return False
    after = start + len(identifier)
    operator = b"=" if declaration.role == "keyword" else b"=="
    return (
        start <= declaration.match_span[0] < after
        and source.data[start:after] == identifier
        and source.data[after:literal[0] - 1].strip(b" \t") == operator
    )


def _bind_python(
    row: dict[str, Any], record: _Record, proof: PythonDeclaration, label: str,
) -> bool:
    if record.decoded_sha256 != proof.source_sha256:
        return False
    return sum(
        (literal := secrets._literal_string(record.source, value)) is not None
        and literal[2] == label
        and _python_site(record.source, operand, literal, proof)
        and _python_match(row, record.source, proof.match_span, literal)
        for operand, value in _python_operands(record.original, proof)
    ) == 1


def _proves(row: dict[str, Any], record: _Record, proof: _Proof) -> bool:
    declaration = proof.declaration
    if isinstance(declaration, PythonDeclaration):
        return _bind_python(row, record, declaration, proof.label)
    if not _pinned_bytes(declaration, record):
        return False
    span = _value_span(row, record.source, declaration.match_span)
    return span is not None and _bind_pointer(record, span, declaration.pointer, proof.label)


def _one_proof(row: dict[str, Any], record: _Record, proofs: tuple[_Proof, ...]) -> bool:
    return sum(_proves(row, record, proof) for proof in proofs) == 1


def _declared_rows(
    findings: list[dict[str, Any]], proofs: dict[str, tuple[_Proof, ...]],
) -> dict[str, list[tuple[int, dict[str, Any]]]]:
    rows = defaultdict(list)
    for index, row in enumerate(findings):
        path = row["File"]
        if path in proofs and _raw_row(row, path):
            rows[path].append((index, row))
    return rows


def _candidates(
    findings: list[dict[str, Any]], directory: Path, proofs: dict[str, tuple[_Proof, ...]],
) -> dict[bool, set[int]]:
    by_archive = defaultdict(set)
    for path, rows in _declared_rows(findings, proofs).items():
        record = _load_record(directory / path)
        if record is None:
            continue
        by_archive[record.source.gzip is not None].update(
            index for index, row in rows if _one_proof(row, record, proofs[path])
        )
    return by_archive


def verified_rows(
    findings: list[dict[str, Any]], directory: Path, run_report: secrets._ReportRun, *,
    proofs: dict[str, tuple[_Proof, ...]],
) -> set[int]:
    """Return only declared rows reproduced by a direct scan of the same snapshot."""
    candidates = _candidates(findings, directory, proofs)
    return (
        secrets._unique_direct_rows(findings, candidates[False], run_report, archive_depth=0)
        | secrets._unique_direct_rows(findings, candidates[True], run_report, archive_depth=1)
    )


def prepare_scan(
    declarations: tuple[ModelDeclaration, ...], paths: dict[str, bool], tracked: set[str],
    read_blob: secrets._ReadGitBlob,
) -> secrets._VerifyModels:
    return partial(verified_rows, proofs=prepare(declarations, paths, tracked, read_blob))
