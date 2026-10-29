"""Tokenize shell commands without treating comments or quoted text as code."""

from __future__ import annotations

import bisect
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from .owners_match import Occurrence, script_index
from .policy import GateError


@dataclass(frozen=True)
class Token:
    value: str | None
    start: int
    end: int
    line: int
    operator: bool = False
    assignment: bool = False


def _shifted(token: Token, offset: int, line_offset: int) -> Token:
    return Token(
        token.value,
        token.start + offset,
        token.end + offset,
        token.line + line_offset,
        token.operator,
        token.assignment,
    )


def _skip_quote(source: str, index: int) -> int:
    quote = source[index]
    index += 1
    while index < len(source):
        if source[index] == "\\" and quote != "'":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return len(source) + 1


def _skip_special(source: str, index: int) -> int | None:
    if source[index] == "\\":
        return index + 2
    if source[index] in "'\"`":
        return _skip_quote(source, index)
    if _starts_comment(source, index):
        end = source.find("\n", index)
        return len(source) if end < 0 else end
    return None


def _starts_comment(source: str, index: int) -> bool:
    if source[index] != "#":
        return False
    return index == 0 or source[index - 1].isspace() or source[index - 1] in ";|&("


def _substitution_depth(char: str, depth: int) -> int:
    return depth + (char == "(") - (char == ")")


def _substitution_end(source: str, start: int, relative: str) -> int:
    depth = 1
    index = start + 2
    while index < len(source):
        char = source[index]
        following = _skip_special(source, index)
        if following is not None:
            index = following
            continue
        depth = _substitution_depth(char, depth)
        if depth == 0:
            return index
        index += 1
    raise GateError(f"cannot tokenize shell {relative}: unterminated command substitution")


class _Scanner:
    def __init__(self, relative: str, source: str) -> None:
        self.relative = relative
        self.source = source
        self.mask = list(source)
        self.lines = [-1] + [i for i, char in enumerate(source) if char == "\n"]
        self.tokens: list[Token] = []
        self.heredocs: list[tuple[str, bool]] = []
        self.expect_heredoc: str | None = None
        self.substitutions: list[list[Token]] = []

    def blank(self, start: int, end: int) -> None:
        for index in range(start, end):
            if self.mask[index] not in "\r\n":
                self.mask[index] = " "

    def add(
        self,
        value: str | None,
        start: int,
        end: int,
        *,
        operator: bool = False,
        assignment: bool = False,
    ) -> None:
        line = bisect.bisect_left(self.lines, start)
        self.tokens.append(Token(value, start, end, line, operator, assignment))

    def _embedded(self, inner: int, end: int) -> None:
        tokens, code, nested = _Scanner(self.relative, self.source[inner:end]).scan()
        line_offset = bisect.bisect_left(self.lines, inner) - 1
        self.substitutions.append([_shifted(token, inner, line_offset) for token in tokens])
        self.substitutions.extend(
            [_shifted(token, inner, line_offset) for token in group] for group in nested
        )
        self.mask[inner:end] = code

    def substitution(self, start: int) -> int:
        end = _substitution_end(self.source, start, self.relative)
        self._embedded(start + 2, end)
        return end + 1

    def backtick(self, start: int) -> int:
        end = _skip_quote(self.source, start)
        if end > len(self.source):
            raise GateError(f"cannot tokenize shell {self.relative}: unterminated backtick")
        self.blank(start, end)
        self._embedded(start + 1, end - 1)
        return end

    def _quoted_substitution(self, quote: str, index: int) -> bool:
        return (
            quote == '"'
            and self.source.startswith("$(", index)
            and not self.source.startswith("$((", index)
        )

    def _quote_escape(self, quote: str, index: int) -> bool:
        return self.source[index] == "\\" and quote != "'"

    def _quoted_backtick(self, quote: str, index: int) -> bool:
        return quote == '"' and self.source[index] == "`"

    def quote(self, index: int) -> int:
        quote = self.source[index]
        start = index
        index += 1
        while index < len(self.source):
            char = self.source[index]
            if self._quote_escape(quote, index):
                index += 2
                continue
            if self._quoted_substitution(quote, index):
                self.blank(start, index + 2)
                index = self.substitution(index)
                start = index - 1
                continue
            if self._quoted_backtick(quote, index):
                self.blank(start, index + 1)
                index = self.backtick(index)
                start = index - 1
                continue
            if char == quote:
                self.blank(start, index + 1)
                return index + 1
            index += 1
        raise GateError(f"cannot tokenize shell {self.relative}: unterminated {quote} quote")

    def _word_boundary(self, index: int) -> bool:
        char = self.source[index]
        if self.source.startswith(("<(", ">("), index):
            return False
        return char.isspace() or char in "|&;()<>"

    def arithmetic(self, start: int) -> int:
        end = _substitution_end(self.source, start, self.relative)
        index = start + 3
        while index < end:
            if self.source.startswith("$(", index) and not self.source.startswith("$((", index):
                index = self.substitution(index)
            elif self.source[index] == "`":
                index = self.backtick(index)
            else:
                index += 1
        return end + 1

    def _parameter_part(self, index: int) -> int | None:
        if self.source[index] == "`":
            return self.backtick(index)
        if self.source[index] in "'\"":
            return self.quote(index)
        if self.source[index] == "\\":
            return index + 2
        return self._expansion(index)

    def parameter(self, start: int) -> int:
        index = start + 2
        depth = 1
        while index < len(self.source):
            following = self._parameter_part(index)
            if following is not None:
                index = following
                continue
            depth += (self.source[index] == "{") - (self.source[index] == "}")
            index += 1
            if not depth:
                return index
        raise GateError(f"cannot tokenize shell {self.relative}: unterminated parameter expansion")

    def _expansion(self, index: int) -> int | None:
        if self.source.startswith("$((", index):
            return self.arithmetic(index)
        if self.source.startswith(("$(", "<(", ">("), index):
            return self.substitution(index)
        if self.source.startswith("${", index):
            return self.parameter(index)
        return None

    def _word_part(self, index: int) -> tuple[int, bool]:
        char = self.source[index]
        if char == "`":
            return self.backtick(index), False
        if char in "'\"":
            end = self.quote(index)
            return end, _literal_quote(self.source[index:end])
        if char == "\\":
            self.blank(index, min(index + 2, len(self.source)))
            return index + 2, True
        end = self._expansion(index)
        if end is not None:
            return end, False
        return index + 1, _literal_char(self.source, index)

    def _word_end(self, index: int) -> tuple[int, bool]:
        literal = True
        while index < len(self.source):
            if self._word_boundary(index):
                break
            index, part_literal = self._word_part(index)
            literal = literal and part_literal
        return index, literal

    def _record_heredoc(self, raw: str) -> None:
        if self.expect_heredoc is not None:
            delimiter = raw.strip("'\"")
            self.heredocs.append((delimiter, self.expect_heredoc == "<<-"))
            self.expect_heredoc = None

    def word(self, index: int) -> int:
        start = index
        index, literal = self._word_end(index)
        raw = self.source[start:index]
        self._record_heredoc(raw)
        value = _literal_word(raw) if literal else None
        self.add(value, start, index, assignment=bool(_ASSIGNMENT.match(raw)))
        return index

    def _heredoc(self, index: int, delimiter: str, strip_tabs: bool) -> int:
        while index < len(self.source):
            end = self.source.find("\n", index)
            end = len(self.source) if end < 0 else end + 1
            line = self.source[index:end].rstrip("\r\n")
            self.blank(index, end)
            index = end
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                return index
        raise GateError(
            f"cannot tokenize shell {self.relative}: missing heredoc delimiter {delimiter!r}"
        )

    def heredoc_body(self, index: int) -> int:
        for delimiter, strip_tabs in self.heredocs:
            index = self._heredoc(index, delimiter, strip_tabs)
        self.heredocs.clear()
        return index

    def operator(self, index: int) -> int:
        source = self.source
        op = next(
            (
                item
                for item in ("&>>", "<<-", "&&", "||", ";;", "<<", ">>", ">&", "<&", "&>")
                if source.startswith(item, index)
            ),
            source[index],
        )
        end = index + len(op)
        self.add(op, index, end, operator=True)
        if op in ("<<", "<<-"):
            self.expect_heredoc = op
        return end

    def _code_token(self, index: int) -> int:
        if self.source.startswith(("<(", ">("), index):
            return self.word(index)
        if self.source[index] in "|&;()<>":
            return self.operator(index)
        return self.word(index)

    def _comment(self, index: int) -> int:
        end = self.source.find("\n", index)
        end = len(self.source) if end < 0 else end
        self.blank(index, end)
        return end

    def _advance(self, index: int) -> int:
        char = self.source[index]
        if self.source.startswith("\\\n", index):
            self.blank(index, index + 2)
            return index + 2
        if char == "#":
            return self._comment(index)
        if char == "\n":
            self.add("\n", index, index + 1, operator=True)
            return self.heredoc_body(index + 1)
        if char.isspace():
            return index + 1
        return self._code_token(index)

    def scan(self) -> tuple[list[Token], str, list[list[Token]]]:
        index = 0
        while index < len(self.source):
            index = self._advance(index)
        return self.tokens, "".join(self.mask), self.substitutions


_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\[[^]\n]*\])?\+?=")
_RESERVED = {"if", "then", "elif", "else", "fi", "while", "until", "do", "done", "!", "{", "}"}
_SEPARATORS = {"\n", "|", "||", "&&", "&", ";", ";;", "(", ")"}
_REDIRECTS = {"<", ">", "<<", "<<-", ">>", ">&", "<&", "&>", "&>>"}


def _literal_quote(raw: str) -> bool:
    if raw.startswith("'"):
        return True
    if raw.startswith("`"):
        return False
    return not re.search(r"(?<!\\)(?:\\\\)*[$`]", raw)


def _literal_word(raw: str) -> str | None:
    if raw.startswith("~"):
        return None
    return shlex.split(raw)[0] if raw else ""


def _literal_char(source: str, index: int) -> bool:
    if source[index] in "$*?":
        return False
    if source[index] == "[" and re.match(r"\[[^]\s]+\]", source[index:]):
        return False
    return not (source[index] == "{" and re.match(r"\{[^{}\s]*(?:,|\.\.)[^{}\s]*\}", source[index:]))


class _Commands:
    def __init__(self) -> None:
        self.commands: list[list[Token]] = []
        self.current: list[Token] = []
        self.redirect = False

    def flush(self) -> None:
        if self.current:
            self.commands.append(self.current)
            self.current = []

    def _drop_descriptor(self, token: Token) -> None:
        if _is_descriptor(self.current, token):
            self.current.pop()

    def operator(self, token: Token) -> None:
        if token.value in _SEPARATORS:
            self.flush()
            self.redirect = False
        elif token.value in _REDIRECTS:
            self._drop_descriptor(token)
            self.redirect = True

    def add(self, token: Token) -> None:
        if token.operator:
            self.operator(token)
            return
        if self.redirect:
            self.redirect = False
            return
        if _is_prefix(self.current, token):
            return
        self.current.append(token)


def _is_prefix(current: list[Token], token: Token) -> bool:
    return not current and (token.value in _RESERVED or token.assignment)


def _is_descriptor(current: list[Token], operator: Token) -> bool:
    return bool(
        current
        and current[-1].value
        and current[-1].value.isdigit()
        and current[-1].end == operator.start
    )


def _commands(tokens: list[Token]) -> list[list[Token]]:
    builder = _Commands()
    for token in tokens:
        builder.add(token)
    builder.flush()
    return builder.commands


def _shell_event(kind: str, value: str, token: Token, scope: tuple[str, int]) -> Occurrence:
    return Occurrence(kind, value, token.line, token.start, token.end, scope, frozenset({scope}))


def _unanalysable(token: Token, source: str, reason: str) -> Occurrence:
    scope = ("shell", token.start)
    return Occurrence("unanalysable", source[token.start:token.end], token.line, token.start,
                      token.end, scope, frozenset(), reason)


def _script_events(command: list[Token], source: str, scope: tuple[str, int]) -> list[Occurrence]:
    result = script_index([token.value for token in command])
    if result.error_index is not None:
        return [_unanalysable(command[result.error_index], source, result.reason or "unknown")]
    if result.index is not None:
        script = command[result.index]
        assert script.value is not None
        return [_shell_event("shell-script", script.value, script, scope)]
    return []


def _command_events(command: list[Token], source: str) -> list[Occurrence]:
    events: list[Occurrence] = []
    head = command[0]
    if head.value is None:
        return [_unanalysable(head, source, "cannot determine command head")]
    scope = ("shell", head.start)
    events.append(_shell_event("shell-command", head.value, head, scope))
    basename = PurePosixPath(head.value).name
    if basename != head.value:
        events.append(_shell_event("shell-command", basename, head, scope))
    events.extend(_script_events(command, source, scope))
    return events


def shell_events(relative: str, source: str) -> tuple[list[Occurrence], str]:
    tokens, code, substitutions = _Scanner(relative, source).scan()
    commands = _commands(tokens)
    for group in substitutions:
        commands.extend(_commands(group))
    events = [event for command in commands for event in _command_events(command, source)]
    return events, code
