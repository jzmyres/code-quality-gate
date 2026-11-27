"""Bind a redacted scanner match to one integer in a published tokenizer."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .json_input import load_json

MAX_PUBLISHED_BYTES = 32 << 20
MAX_ASSETS = 16
MAX_POINTERS = 256
_MAX_LINE_BYTES = 16 << 10
_VOCABULARY_MODELS = ("BPE", "WordLevel", "WordPiece")
_MEMBER = re.compile(
    rb'[ \t]*(?P<key>"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")'
    rb'[ \t]*:[ \t]*(?P<value>0|[1-9][0-9]*),[ \t]*\r?',
)


@dataclass(frozen=True)
class PublishedVocabulary:
    path: str
    published_url: str
    published_revision: str
    published_sha256: str
    published_size: int
    keys: frozenset[str]
    compressed_sha256: str | None = None
    compressed_size: int | None = None


@dataclass(frozen=True, order=True)
class MemberSpan:
    start: int
    end: int
    key: str


def _redacted_prefix(row: dict[str, Any]) -> bytes | None:
    """Read the exact UTF-8 prefix before a redacted member's decimal value."""
    template = row.get("Match")
    if not isinstance(template, str):
        return None
    prefix, _, suffix = template.partition("REDACTED")
    if (row.get("Secret"), suffix) != ("REDACTED", ","):
        return None
    if not prefix or "\ufffd" in prefix:
        return None
    try:
        return prefix.encode("utf-8")
    except UnicodeEncodeError:
        return None


def _unique_shape(line: bytes, prefix: bytes, suffix: bytes, start: int, end: int) -> bool:
    """Find every line-local reconstruction of the same fixed-width redaction."""
    width = end - start
    position = -1
    unique = None
    while (position := line.find(prefix, position + 1, len(line) - width + len(prefix))) != -1:
        if line[position + width - len(suffix):position + width] == suffix:
            if unique is not None:
                return False
            unique = position
    return unique == start


def _reported_line(
    data: bytes, starts: Sequence[int], row: dict[str, Any],
) -> tuple[bytes, int] | None:
    coordinates = (row.get("StartLine"), row.get("EndLine"), row.get("StartColumn"), row.get("EndColumn"))
    if not all(type(value) is int for value in coordinates):
        return None
    line, end_line, start, end = coordinates
    if not (1 <= line == end_line <= len(starts) and 1 <= start <= end):
        return None
    offset = starts[line - 1]
    stop = starts[line] - 1 if line < len(starts) else len(data)
    return data[offset:stop], offset


def _value_match(line: bytes, row: dict[str, Any], prefix: bytes) -> re.Match[bytes] | None:
    if len(line) > _MAX_LINE_BYTES:
        return None
    member = _MEMBER.fullmatch(line)
    if member is None:
        return None
    start, end = row["StartColumn"] - 1, row["EndColumn"]
    value_start, value_end = member.span("value")
    if (start + len(prefix), end) != (value_start, value_end + 1):
        return None
    if not member.start("key") <= start < member.end("key"):
        return None
    return member


def _decode_member(member: re.Match[bytes], offset: int, keys: frozenset[str]) -> MemberSpan | None:
    try:
        key = json.loads(member["key"].decode("utf-8"))
    except ValueError:
        return None
    if key not in keys:
        return None
    start, end = member.span("value")
    return MemberSpan(offset + start, offset + end, key)


def member_span(
    data: bytes, starts: Sequence[int], row: dict[str, Any], keys: frozenset[str],
) -> MemberSpan | None:
    """Require the reported match to expose exactly one canonical integer member."""
    source = _reported_line(data, starts, row)
    prefix = _redacted_prefix(row)
    if source is None or prefix is None:
        return None
    line, offset = source
    member = _value_match(line, row, prefix)
    if member is None:
        return None
    if not _unique_shape(line, prefix, b",", row["StartColumn"] - 1, row["EndColumn"]):
        return None
    return _decode_member(member, offset, keys)


def _vocab(data: bytes | bytearray) -> dict[str, Any]:
    document = load_json(data.decode("utf-8"))
    model = document.get("model") if isinstance(document, dict) else None
    if not isinstance(model, dict) or model.get("type") not in _VOCABULARY_MODELS:
        raise ValueError("expected a tokenizer model with an object vocabulary")
    vocab = model.get("vocab")
    if not isinstance(vocab, dict):
        raise ValueError("expected a tokenizer vocabulary object")
    return vocab


def _integer_vocabulary(data: bytes) -> dict[str, int]:
    vocab = _vocab(data)
    if any(type(value) is not int or value < 0 for value in vocab.values()):
        raise ValueError("expected nonnegative integer token IDs")
    return vocab


def _mark_spans(data: bytes, spans: set[MemberSpan]) -> tuple[bytearray, dict[MemberSpan, str]]:
    marked = bytearray()
    markers = {}
    end = 0
    for span in sorted(spans):
        if not end <= span.start < span.end <= len(data):
            raise ValueError("expected disjoint member spans")
        marker = f"published-vocabulary-position-{span.start}"
        marked.extend(data[end:span.start])
        marked.extend(json.dumps(marker).encode("ascii"))
        markers[span] = marker
        end = span.end
    marked.extend(data[end:])
    return marked, markers


def proven_spans(data: bytes, spans: set[MemberSpan]) -> set[MemberSpan]:
    """Reparse each uniquely marked integer to prove its exact structural pointer."""
    if not spans:
        return set()
    try:
        vocab = _integer_vocabulary(data)
        document, markers = _mark_spans(data, spans)
        changed = _vocab(document)
        return {
            span for span, marker in markers.items()
            if changed.get(span.key) == marker
            and str(vocab.get(span.key)).encode("ascii") == data[span.start:span.end]
        }
    except (ValueError, RecursionError):
        return set()
