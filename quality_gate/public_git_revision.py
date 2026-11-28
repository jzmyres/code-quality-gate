"""Prove occurrences of published tokenizer revisions from archived Git objects."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache, partial
from itertools import islice
from pathlib import Path
from typing import Any

from . import secrets
from .json_input import load_json


MAX_OBJECT_BYTES = 64 << 10
MAX_RECORDS = 16
REPOSITORY_URL = re.compile(
    r"https://huggingface\.co/([A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95})",
)
REVISION = re.compile(r"[0-9a-f]{40}")
_TREE_HEADER = re.compile(rb"tree ([0-9a-f]{40})")
_TREE_ENTRY = re.compile(rb"(100644|100755|120000|160000|40000) ([^/\0]+)\0(.{20})", re.DOTALL)
_BLOCK_MARKER = re.compile(rb"(?m)^[ \t]*(?:`{3,}|~{3,}|<)[^\n]*")


@dataclass(frozen=True)
class ObjectBody:
    payload: secrets.GitPayload
    sha256: str

    def read(self, read_blob: secrets._ReadGitBlob, kind: str, object_id: str) -> bytes | None:
        if not 0 < self.payload.size <= MAX_OBJECT_BYTES:
            return None
        checked = read_blob(self.payload)
        if checked is None or checked[1] != self.sha256:
            return None
        return checked[0] if _git_oid(kind, checked[0]) == object_id else None


def _git_oid(kind: str, body: bytes) -> str:
    digest = hashlib.sha1(f"{kind} {len(body)}\0".encode("ascii"), usedforsecurity=False)
    digest.update(body)
    return digest.hexdigest()


def _commit_tree(body: bytes) -> str | None:
    headers, separator, _message = body.partition(b"\n\n")
    first, _, rest = headers.partition(b"\n")
    tree = _TREE_HEADER.fullmatch(first)
    if not separator or tree is None:
        return None
    keys = [line.partition(b" ")[0] for line in rest.split(b"\n")]
    counts = (keys.count(b"tree"), keys.count(b"author"), keys.count(b"committer"))
    return tree[1].decode("ascii") if counts == (0, 1, 1) and b"\0" not in body else None


def _tree_modes(body: bytes) -> dict[bytes, bytes]:
    modes = {}
    position = 0
    while position < len(body):
        entry = _TREE_ENTRY.match(body, position)
        if entry is None:
            return {}
        mode, name, identity = entry.groups()
        if name in modes or name in (b".", b"..") or identity == bytes(20):
            return {}
        modes[name] = mode
        position = entry.end()
    return modes


@dataclass(frozen=True)
class Publication:
    repository: str
    revision: str
    commit: ObjectBody
    tree: ObjectBody

    def verified(self, read_blob: secrets._ReadGitBlob) -> bool:
        commit = self.commit.read(read_blob, "commit", self.revision)
        tree_id = _commit_tree(commit) if commit is not None else None
        if tree_id is None:
            return False
        tree = self.tree.read(read_blob, "tree", tree_id)
        modes = _tree_modes(tree or b"")
        return all(
            modes.get(name) in (b"100644", b"100755")
            for name in (b"tokenizer.json", b"tokenizer_config.json")
        )


@dataclass(frozen=True)
class Declaration:
    record: str
    pointer: tuple[str, ...]
    match_span: tuple[int, int]
    record_sha256: str
    publication: Publication


def _json_region(data: bytes, markdown: bool) -> tuple[int, int] | None:
    if not markdown:
        return 0, len(data)
    markers = list(islice(_BLOCK_MARKER.finditer(data), 3))
    if [marker.group() for marker in markers] != [b"```json", b"```"]:
        return None
    opening, closing = markers
    start = opening.start()
    if start and data[start - 2:start] != b"\n\n":
        return None
    return opening.end() + 1, closing.start()


@dataclass(frozen=True)
class _Document:
    record: secrets._Record
    region: tuple[int, int]
    original: Any

    @classmethod
    def read(cls, directory: Path, declaration: Declaration) -> _Document | None:
        record = secrets._read_record(directory / declaration.record)
        if record is None or hashlib.sha256(record.data).hexdigest() != declaration.record_sha256:
            return None
        region = _json_region(record.data, declaration.record.endswith(".md"))
        if region is None:
            return None
        start, end = region
        try:
            record.data.decode("utf-8")
            original = load_json(record.data[start:end].decode("utf-8"))
        except (ValueError, RecursionError):
            return None
        return cls(record, region, original)

    def proves(self, row: dict[str, Any], declaration: Declaration) -> bool:
        start, end = self.region
        match_start, match_end = declaration.match_span
        publication = declaration.publication
        repository = secrets._pointer_value(self.original, (*declaration.pointer[:-1], "tokenizer"))
        if repository != publication.repository or not start <= match_start < match_end <= end:
            return False
        span = secrets._direct_value_span(row, self.record, declaration.match_span)
        return span is not None and secrets._bind_json_pointer(
            self.record.data[start:end], self.original, (span[0] - start, span[1] - start),
            declaration.pointer, publication.revision,
        )


def _verified_rows(
    findings: list[dict[str, Any]], directory: Path, run_report: secrets._ReportRun, *,
    proofs: dict[str, Declaration],
) -> set[int]:
    read = cache(partial(_Document.read, directory))
    candidates = set()
    for index, row in enumerate(findings):
        path = row["File"]
        declaration = proofs.get(path)
        if declaration is None or not secrets._direct_assignment(row, path):
            continue
        document = read(declaration)
        if document is not None and document.proves(row, declaration):
            candidates.add(index)
    return secrets._unique_direct_rows(findings, candidates, run_report, archive_depth=0)


def prepare_scan(
    declarations: tuple[Declaration, ...], paths: dict[str, bool], tracked: set[str],
    read_blob: secrets._ReadGitBlob,
) -> secrets._VerifyRows:
    verify = cache(lambda publication: publication.verified(read_blob))
    proofs = {
        declaration.record: declaration for declaration in declarations
        if paths.get(declaration.record) and declaration.record in tracked and verify(declaration.publication)
    }
    return partial(_verified_rows, proofs=proofs)
