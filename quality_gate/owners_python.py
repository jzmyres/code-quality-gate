"""Python syntax events for single-owner rules."""

from __future__ import annotations

import ast
import io
import tokenize

from .owners_match import Occurrence, script_index
from .policy import GateError


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _call_scopes(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> frozenset[tuple[str, int]]:
    scopes = {("python", id(node))}
    child: ast.AST = node
    while child in parents:
        parent = parents[child]
        if isinstance(parent, ast.Call):
            if not parent.args or parent.args[0] is not child:
                break
            scopes.add(("python", id(parent)))
        child = parent
    return frozenset(scopes)


def _event(
    kind: str,
    value: str,
    node: ast.AST,
    scope: ast.AST,
    covers: frozenset[tuple[str, int]] | None = None,
) -> Occurrence:
    key = ("python", id(scope))
    return Occurrence(kind, value, node.lineno, 0, 0, key, covers or frozenset({key}))


def _call_event(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> list[Occurrence]:
    name = _name(node.func)
    if name is None:
        return []
    return [_event("python-call", name, node, node, _call_scopes(node, parents))]


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _argv_scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    parent = parents.get(node)
    if isinstance(parent, ast.Call) and parent.args and parent.args[0] is node:
        return parent
    if isinstance(parent, ast.Return):
        return node
    return None


def _script_event(node: ast.List | ast.Tuple, scope: ast.AST, source: str) -> list[Occurrence]:
    words = [_literal(item) for item in node.elts]
    result = script_index(words)
    if result.error_index is not None:
        item = node.elts[result.error_index]
        word = words[result.error_index] or ast.get_source_segment(source, item) or "<expression>"
        key = ("python", id(scope))
        return [Occurrence("unanalysable", word, item.lineno, 0, 0, key, frozenset(), result.reason)]
    if result.index is not None:
        value = words[result.index]
        assert value is not None
        return [_event("python-script", value, node.elts[result.index], scope)]
    return []


def _argv_event(node: ast.AST, parents: dict[ast.AST, ast.AST], source: str) -> list[Occurrence]:
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return []
    first = _literal(node.elts[0])
    if first is None:
        return []
    scope = _argv_scope(node, parents)
    if scope is None:
        return []
    return [_event("python-argv", first, node, scope), *_script_event(node, scope, source)]


def _import_events(node: ast.AST) -> list[Occurrence]:
    if isinstance(node, ast.Import):
        return [_event("python-import", alias.name, node, node) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        module = "." * node.level + (node.module or "")
        return [_event("python-import", module, node, node)]
    return []


def python_events(relative: str, source: str) -> list[Occurrence]:
    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError) as error:
        raise GateError(f"cannot parse Python {relative}: {error}") from error
    parents = _parents(tree)
    events: list[Occurrence] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            events.extend(_call_event(node, parents))
        events.extend(_argv_event(node, parents, source))
        events.extend(_import_events(node))
    return events


def _mask_line(line: list[str], left: int, right: int) -> None:
    for column in range(left, right):
        if line[column] not in "\r\n":
            line[column] = " "


def _mask_range(lines: list[list[str]], start: tuple[int, int], end: tuple[int, int]) -> None:
    for row in range(start[0] - 1, end[0]):
        left = start[1] if row == start[0] - 1 else 0
        right = end[1] if row == end[0] - 1 else len(lines[row])
        _mask_line(lines[row], left, right)


def _mask_tokens(lines: list[list[str]], source: str) -> None:
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in (
            tokenize.STRING,
            tokenize.COMMENT,
            tokenize.FSTRING_START,
            tokenize.FSTRING_MIDDLE,
            tokenize.FSTRING_END,
        ):
            _mask_range(lines, token.start, token.end)


def python_code(relative: str, source: str) -> str:
    lines = [list(line) for line in source.splitlines(keepends=True)]
    try:
        _mask_tokens(lines, source)
    except (tokenize.TokenError, IndentationError, SyntaxError) as error:
        raise GateError(f"cannot tokenize Python {relative}: {error}") from error
    return "".join("".join(line) for line in lines)
