"""Prove one JSON scanner occurrence from a trusted public hardware catalogue."""
from __future__ import annotations

import ast
import hashlib
from collections import defaultdict
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
class _Proof:
    declaration: Declaration
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


def _selected(declaration: Declaration, paths: dict[str, bool], tracked: set[str]) -> bool:
    path = declaration.record
    return (
        bool(paths.get(path)) and path in tracked and path.endswith((".json", ".json.gz"))
        and path != declaration.catalogue.payload.path
        and path.endswith(".json.gz") == (declaration.compressed_sha256 is not None)
    )


def prepare(
    declarations: tuple[Declaration, ...], paths: dict[str, bool], tracked: set[str],
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
    try:
        original = load_json(source.data.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    digest = source.gzip.decoded if source.gzip else hashlib.sha256(source.data).hexdigest()
    return _Record(source, digest, original)


def _pinned_bytes(proof: Declaration, record: _Record) -> bool:
    archive = record.source.gzip
    compressed = archive.compressed if archive else None
    return proof.decoded_sha256 == record.decoded_sha256 and proof.compressed_sha256 == compressed


def _proves(row: dict[str, Any], record: _Record, proof: _Proof) -> bool:
    declaration = proof.declaration
    if not _pinned_bytes(declaration, record):
        return False
    span = secrets._direct_value_span(row, record.source, declaration.match_span)
    return span is not None and secrets._bind_json_pointer(
        record.source.data, record.original, span, declaration.pointer, proof.label,
    )


def _one_proof(row: dict[str, Any], record: _Record, proofs: tuple[_Proof, ...]) -> bool:
    return sum(_proves(row, record, proof) for proof in proofs) == 1


def _declared_rows(
    findings: list[dict[str, Any]], proofs: dict[str, tuple[_Proof, ...]],
) -> dict[str, list[tuple[int, dict[str, Any]]]]:
    rows = defaultdict(list)
    for index, row in enumerate(findings):
        path = row["File"]
        if path in proofs and secrets._direct_assignment(row, path):
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
    declarations: tuple[Declaration, ...], paths: dict[str, bool], tracked: set[str],
    read_blob: secrets._ReadGitBlob,
) -> secrets._VerifyRows:
    return partial(verified_rows, proofs=prepare(declarations, paths, tracked, read_blob))
