"""Locations and scopes shared by the single-owner pattern matchers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re


@dataclass(frozen=True)
class Occurrence:
    kind: str
    value: str
    line: int
    start: int
    end: int
    scope: tuple[str, int]
    cover_scopes: frozenset[tuple[str, int]]


def covered(forbidden: Occurrence, allowed: Occurrence) -> bool:
    if forbidden.kind == allowed.kind == "text-regex":
        return allowed.start <= forbidden.start and allowed.end >= forbidden.end
    if forbidden.scope in allowed.cover_scopes:
        return True
    return False


def interpreter(word: str) -> bool:
    name = PurePosixPath(word).name
    return name in {"sh", "bash", "dash", "zsh", "ksh", "python"} or bool(
        re.fullmatch(r"python[0-9]+(?:\.[0-9]+)*", name)
    )


def _no_script_option(value: str, python: bool) -> bool:
    return value.startswith(("-c", "-m")) or (not python and "c" in value[1:])


def _is_operand(value: str) -> bool:
    return not value.startswith("-") or value == "-"


def _consumes_option(value: str, python: bool) -> bool:
    return value in (("-W", "-X") if python else ("-o", "-O"))


def _option_step(value: str | None, python: bool) -> int:
    if value is None:
        return -1
    if _is_operand(value):
        return 0
    if _no_script_option(value, python):
        return -1
    return 1 + int(_consumes_option(value, python))


def _script_position(words: list[str | None], python: bool) -> int | None:
    index = 1
    while index < len(words):
        if words[index] == "--":
            return index + 1
        step = _option_step(words[index], python)
        if step < 0:
            return None
        if step == 0:
            return index
        index += step
    return None


def _valid_script(words: list[str | None], index: int | None) -> bool:
    return index is not None and index < len(words) and words[index] not in (None, "-")


def script_index(words: list[str | None]) -> int | None:
    if not words or words[0] is None or not interpreter(words[0]):
        return None
    python = PurePosixPath(words[0]).name.startswith("python")
    index = _script_position(words, python)
    if not _valid_script(words, index):
        return None
    return index
