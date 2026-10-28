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


_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh"})
_PYTHONS = re.compile(r"python[0-9]+(?:\.[0-9]+)*")
_SHELL_OPERANDS = frozenset({"o", "O"})
_PYTHON_OPERANDS = frozenset({"W", "X"})
_SHELL_LONG_OPERANDS = frozenset({"--rcfile", "--init-file"})


def _kind(word: str) -> str | None:
    name = PurePosixPath(word).name
    if name in _SHELLS:
        return "shell"
    if name == "python" or _PYTHONS.fullmatch(name):
        return "python"
    return None


def _is_operand(value: str) -> bool:
    return not value.startswith("-") or value == "-"


def _long_step(value: str, kind: str) -> int:
    name, attached, _operand = value.partition("=")
    if kind == "shell" and name in _SHELL_LONG_OPERANDS and not attached:
        return 2
    return 1


def _command_option(letter: str, kind: str) -> bool:
    return letter == "c" or (kind == "python" and letter == "m")


def _operand_width(letters: str, position: int, operands: frozenset[str]) -> int:
    if letters[position] not in operands:
        return 0
    return 2 if position + 1 == len(letters) else 1


def _short_step(value: str, kind: str) -> int:
    letters = value[1:]
    operands = _SHELL_OPERANDS if kind == "shell" else _PYTHON_OPERANDS
    for position, letter in enumerate(letters):
        if _command_option(letter, kind):
            return -1
        width = _operand_width(letters, position, operands)
        if width:
            return width
    return 1


def _option_step(value: str | None, kind: str) -> int:
    if value is None:
        return -1
    if _is_operand(value):
        return 0
    if value.startswith("--"):
        return _long_step(value, kind)
    return _short_step(value, kind)


def _script_position(words: list[str | None], kind: str) -> int | None:
    index = 1
    while index < len(words):
        if words[index] == "--":
            return index + 1
        step = _option_step(words[index], kind)
        if step < 0:
            return None
        if step == 0:
            return index
        index += step
    return None


def _valid_script(words: list[str | None], index: int | None) -> bool:
    return index is not None and index < len(words) and words[index] not in (None, "-")


def script_index(words: list[str | None]) -> int | None:
    if not words or words[0] is None:
        return None
    kind = _kind(words[0])
    if kind is None:
        return None
    index = _script_position(words, kind)
    if not _valid_script(words, index):
        return None
    return index
