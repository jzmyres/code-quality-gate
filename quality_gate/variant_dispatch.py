"""Variant dispatch: one vocabulary declared once, and one reader per format.

Every selected Python and shell file yields owners: a Python function, a
module-level table, a shell function or a shell file's top-level statements.
Each owner's set is the string literals it treats as a vocabulary.  Two owners
that share at least two literals belong to one finding, whose remedy is one
declared table read through one path.  Python only, a second rule reports a
function that guesses a format by trying two same-annotation readers in a
fallback chain.  A missing or invalid input is a configuration error, never a
skipped rule, and the check has no baseline or exemption list.
"""
from __future__ import annotations

import ast
import itertools
import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import DiffBase, _regular_interpreter, diff_base
from .policy import ConfigError, GateError, _optional_string
from .python_crap import (
    _called_name,
    _function_identity,
    _literal_flags,
    _start_line,
)
from .python_shape import SCOPES, _diff_lines, _parse_tree, _read_source, _touched
from .ratchet import Domain, Finding, Location
from .runner import mark_step
from .verification import _is_python_program


if TYPE_CHECKING:
    from .adapters import ParsedSpec


METRIC_VERSION = "variant-dispatch/1"
KIND_FUNCTION = "function"
KIND_TABLE = "table"
KIND_TOP_LEVEL = "top level"
TOP_LEVEL_NAME = "<module>"
_SHELL_INTERPRETERS = frozenset({"sh", "bash"})
_FORBIDDEN = frozenset("*?[$")
_LITERAL_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*")
_SHELL_FUNCTION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{\s*$")
_CASE = re.compile(r"^\s*case\b.*\bin\s*$")
_ARRAY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\((.*)\)\s*$")
_SUBJECT = (
    r'"\$\{([A-Za-z_][A-Za-z0-9_]*):-\}"'
    r'|"\$([A-Za-z_][A-Za-z0-9_]*)"'
    r"|\$\{([A-Za-z_][A-Za-z0-9_]*):-\}"
    r"|\$([A-Za-z_][A-Za-z0-9_]*)"
)
_WORD = r'("[^"]*"|\'[^\']*\'|\S+)'
_BRACKET_TEST = re.compile(
    r"\[\[\s*(?:" + _SUBJECT + r")\s*(?:==|!=|=)\s*" + _WORD + r"\s*\]\]"
)
_SINGLE_TEST = re.compile(
    r"(?<!\[)\[\s+(?:" + _SUBJECT + r")\s*=\s*" + _WORD + r"\s*\](?!\])"
)
_VSD_HEADER = (
    'VSD variant-dispatch: {literals} are listed in {count} places: {places}\n'
    "Declare this vocabulary once, in one table, and read every per-variant "
    "difference through it."
)


@dataclass(frozen=True)
class VariantSpec:
    scope: str
    base: str


@dataclass(frozen=True)
class Owner:
    path: str
    name: str
    kind: str
    start_line: int
    end_line: int
    literals: frozenset[str]


@dataclass(frozen=True)
class Candidate:
    """One finding and the owners a changed-scope run may judge it by."""

    finding: Finding
    owners: tuple[Owner, ...]


def _variant_dispatch_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    scope = _optional_string(raw, "scope", "tree", path, full_key)
    if scope not in SCOPES:
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of changed, tree; "
            f"got {scope!r}"
        )
    spec = VariantSpec(
        scope, _optional_string(raw, "base", "HEAD", path, full_key)
    )
    return ParsedSpec(spec, METRIC_VERSION, ("static",), threshold=0)


def _has_letter(value: str) -> bool:
    return any(char.isalpha() for char in value)


def _text_literal(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _has_letter(node.value)
    ):
        return node.value
    return None


def _subject(node: ast.AST) -> str | None:
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ast.dump(node)
    return None


def _string_keys(display: ast.Dict) -> list[str] | None:
    keys: list[str] = []
    for key in display.keys:
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return None
        keys.append(key.value)
    return keys


def _key_literals(display: ast.Dict, minimum: int) -> frozenset[str] | None:
    keys = _string_keys(display)
    if keys is None or len(keys) < minimum:
        return None
    return frozenset(key for key in keys if _has_letter(key))


def _display_words(node: ast.AST) -> list[str]:
    words: list[str] = []
    for element in node.elts:
        if isinstance(element, (ast.Tuple, ast.List, ast.Set)):
            words.extend(_display_words(element))
        elif (
            isinstance(element, ast.Constant)
            and isinstance(element.value, str)
        ):
            words.append(element.value)
    return words


def _word_display(node: ast.AST, minimum: int) -> frozenset[str] | None:
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return None
    words = _display_words(node)
    if len(words) < minimum:
        return None
    return frozenset(word for word in words if _has_letter(word))


def _declared_literals(node: ast.AST) -> frozenset[str] | None:
    if isinstance(node, ast.Dict):
        return _key_literals(node, 2)
    if (
        isinstance(node, ast.Call)
        and _called_name(node) == "frozenset"
        and len(node.args) == 1
        and not node.keywords
    ):
        return _word_display(node.args[0], 2)
    return _word_display(node, 2)


def _assigned_names(targets: list[ast.AST]) -> list[str]:
    return [
        target.id for target in targets if isinstance(target, ast.Name)
    ]


def _table_names(statement: ast.AST) -> list[str]:
    if isinstance(statement, ast.Assign):
        return _assigned_names(statement.targets)
    if isinstance(statement, ast.AnnAssign):
        return _assigned_names([statement.target])
    return []


def _declared_tables(
    tree: ast.Module,
) -> list[tuple[str, ast.AST, frozenset[str]]]:
    tables: dict[str, tuple[str, ast.AST, frozenset[str]]] = {}
    for statement in tree.body:
        for name in _table_names(statement):
            literals = _declared_literals(
                statement.value
                if isinstance(statement, (ast.Assign, ast.AnnAssign))
                else statement
            )
            if literals is not None:
                tables[name] = (name, statement, literals)
    return list(tables.values())


def _selection_parts(
    node: ast.AST,
) -> tuple[ast.AST | None, ast.AST | None]:
    if isinstance(node, ast.Subscript):
        return node.value, node.slice
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        return node.func.value, node.args[0]
    return None, None


def _display_key_literals(
    display: ast.AST, key: ast.AST
) -> frozenset[str]:
    if not isinstance(display, ast.Dict) or _literal_flags(key)[0]:
        return frozenset()
    return _key_literals(display, 2) or frozenset()


def _selection_literals(node: ast.AST) -> frozenset[str]:
    display, key = _selection_parts(node)
    if display is None or key is None:
        return frozenset()
    return _display_key_literals(display, key)


def _add_literal(
    subjects: dict[str, set[str]],
    literal_node: ast.AST,
    subject_node: ast.AST,
) -> None:
    subject = _subject(subject_node)
    value = _text_literal(literal_node)
    if subject is not None and value is not None:
        subjects.setdefault(subject, set()).add(value)


def _display_sets(
    left: ast.AST,
    right: ast.AST,
    subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> bool:
    for display_side, other in ((right, left), (left, right)):
        literals = _word_display(display_side, 1)
        if literals is None:
            continue
        subject = _subject(other)
        if subject is not None:
            subjects.setdefault(subject, set()).update(literals)
        else:
            displays.append(literals)
        return True
    return False


def _pair_sets(
    left: ast.AST,
    operation: ast.AST,
    right: ast.AST,
    subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    if isinstance(operation, (ast.In, ast.NotIn)) and _display_sets(
        left, right, subjects, displays
    ):
        return
    if isinstance(operation, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
        _add_literal(subjects, right, left)
        _add_literal(subjects, left, right)


def _compare_literals(
    node: ast.Compare,
    subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    operands = [node.left, *node.comparators]
    for index, operation in enumerate(node.ops):
        _pair_sets(
            operands[index], operation, operands[index + 1],
            subjects, displays,
        )


def _or_pattern_literals(pattern: ast.AST) -> set[str]:
    if not isinstance(pattern, ast.MatchOr):
        return set()
    found: set[str] = set()
    for item in pattern.patterns:
        found.update(_pattern_literals(item))
    return found


def _pattern_literals(pattern: ast.AST) -> set[str]:
    if isinstance(pattern, ast.MatchValue):
        value = _text_literal(pattern.value)
        return set() if value is None else {value}
    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is None:
            return set()
        return _pattern_literals(pattern.pattern)
    return _or_pattern_literals(pattern)


def _match_literals(node: ast.Match) -> frozenset[str]:
    literals: set[str] = set()
    for case in node.cases:
        literals.update(_pattern_literals(case.pattern))
    return frozenset(literals)


def _match_into(
    node: ast.Match,
    _subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    displays.append(_match_literals(node))


def _selection_into(
    node: ast.AST,
    _subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    displays.append(_selection_literals(node))


# The one dispatch table from a node kind to its literal-set reader.
_FUNCTION_SET_HANDLERS = {
    ast.Compare: _compare_literals,
    ast.Match: _match_into,
    ast.Subscript: _selection_into,
    ast.Call: _selection_into,
}


def _scope_walk(nodes: list[ast.AST]):
    """Every node of one scope, without descending into nested functions."""
    for node in nodes:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            continue
        yield node
        yield from _scope_walk(list(ast.iter_child_nodes(node)))


def _vocabulary_literals(
    subjects: dict[str, set[str]], displays: list[frozenset[str]]
) -> frozenset[str]:
    literals: set[str] = set()
    for values in subjects.values():
        if len(values) >= 2:
            literals.update(values)
    for values in displays:
        if len(values) >= 2:
            literals.update(values)
    return frozenset(literals)


def _function_literals(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    subjects: dict[str, set[str]] = {}
    displays: list[frozenset[str]] = []
    for child in _scope_walk(node.body):
        handler = _FUNCTION_SET_HANDLERS.get(type(child))
        if handler is not None:
            handler(child, subjects, displays)
    return _vocabulary_literals(subjects, displays)


def _collect_owners(
    nodes: list[ast.AST], prefix: str, relative: str, owners: list[Owner]
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = _function_identity(node, prefix)
            owners.append(Owner(
                relative,
                name,
                KIND_FUNCTION,
                _start_line(node),
                node.end_lineno or node.lineno,
                _function_literals(node),
            ))
            _collect_owners(node.body, f"{name}.", relative, owners)
            continue
        if isinstance(node, ast.ClassDef):
            _collect_owners(
                node.body, f"{prefix}{node.name}.", relative, owners
            )
            continue
        _collect_owners(
            list(ast.iter_child_nodes(node)), prefix, relative, owners
        )


def _python_owners(relative: str, source: str) -> list[Owner]:
    tree = _parse_tree(relative, source)
    owners = [
        Owner(
            relative,
            name,
            KIND_TABLE,
            statement.lineno,
            statement.end_lineno or statement.lineno,
            literals,
        )
        for name, statement, literals in _declared_tables(tree)
    ]
    _collect_owners(tree.body, "", relative, owners)
    return owners


def _unquote_shell(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"":
        return word[1:-1]
    return word


def _shell_word(raw: str) -> str | None:
    text = _unquote_shell(raw.strip())
    if not text or not _FORBIDDEN.isdisjoint(text) or not _has_letter(text):
        return None
    if _LITERAL_WORD.fullmatch(text) is None:
        return None
    return text


def _shell_matches(line: str):
    return itertools.chain(
        _BRACKET_TEST.finditer(line), _SINGLE_TEST.finditer(line)
    )


def _test_subject(match: Any) -> str | None:
    return next(
        (group for group in match.groups()[:4] if group is not None),
        None,
    )


def _shell_test(line: str, found: dict[str, set[str]]) -> None:
    for match in _shell_matches(line):
        subject = _test_subject(match)
        word = _shell_word(match.group(5))
        if subject is not None and word is not None:
            found.setdefault(subject, set()).add(word)


def _case_patterns(line: str) -> set[str]:
    text = line.strip()
    close = text.find(")")
    if close < 0:
        return set()
    part = text[:close]
    if part.startswith("("):
        part = part[1:]
    found: set[str] = set()
    for alternative in part.split("|"):
        word = _shell_word(alternative)
        if word is not None:
            found.add(word)
    return found


def _case_pattern_literals(lines: list[str]) -> set[str]:
    literals: set[str] = set()
    in_case = False
    for line in lines:
        if not in_case:
            in_case = _CASE.match(line) is not None
            continue
        in_case = line.strip() != "esac"
        if in_case:
            patterns = _case_patterns(line)
            if len(patterns) >= 2:
                literals.update(patterns)
    return literals


def _test_line_literals(lines: list[str]) -> set[str]:
    subjects: dict[str, set[str]] = {}
    for line in lines:
        _shell_test(line, subjects)
    literals: set[str] = set()
    for words in subjects.values():
        if len(words) >= 2:
            literals.update(words)
    return literals


def _shell_lines_literals(lines: list[str]) -> frozenset[str]:
    return frozenset(
        _case_pattern_literals(lines) | _test_line_literals(lines)
    )


@dataclass(frozen=True)
class ShellBlock:
    name: str
    first: int
    last: int


def _shell_blocks(lines: list[str]) -> list[ShellBlock]:
    blocks: list[ShellBlock] = []
    index = 0
    while index < len(lines):
        match = _SHELL_FUNCTION.match(lines[index])
        if match is None:
            index += 1
            continue
        last = index + 1
        while last < len(lines) and lines[last].rstrip() != "}":
            last += 1
        blocks.append(ShellBlock(
            match.group(1), index, min(last, len(lines) - 1)
        ))
        index = last + 1
    return blocks


def _top_level_indexes(
    blocks: list[ShellBlock], total: int
) -> list[int]:
    covered = {
        index
        for block in blocks
        for index in range(block.first, block.last + 1)
    }
    return [index for index in range(total) if index not in covered]


def _array_literals(text: str) -> set[str]:
    found: set[str] = set()
    for raw in text.split():
        word = _shell_word(raw)
        if word is not None:
            found.add(word)
    return found


def _array_owners(
    relative: str, lines: list[str], indexes: list[int]
) -> list[Owner]:
    owners: list[Owner] = []
    for index in indexes:
        match = _ARRAY.match(lines[index])
        if match is None:
            continue
        literals = _array_literals(match.group(2))
        if len(literals) >= 2:
            line = index + 1
            owners.append(Owner(
                relative,
                match.group(1),
                KIND_TABLE,
                line,
                line,
                frozenset(literals),
            ))
    return owners


def _shell_owners(relative: str, source: str) -> list[Owner]:
    lines = source.splitlines()
    blocks = _shell_blocks(lines)
    owners = [
        Owner(
            relative,
            block.name,
            KIND_FUNCTION,
            block.first + 1,
            block.last + 1,
            _shell_lines_literals(lines[block.first:block.last + 1]),
        )
        for block in blocks
    ]
    indexes = _top_level_indexes(blocks, len(lines))
    owners.append(Owner(
        relative,
        TOP_LEVEL_NAME,
        KIND_TOP_LEVEL,
        indexes[0] + 1 if indexes else 1,
        indexes[-1] + 1 if indexes else len(lines),
        _shell_lines_literals([lines[index] for index in indexes]),
    ))
    owners.extend(_array_owners(relative, lines, indexes))
    return owners


def _is_shell_program(root: Path, relative: str) -> bool:
    if relative.endswith(".sh"):
        return True
    try:
        interpreter = _regular_interpreter(root / relative)
    except OSError as error:
        raise GateError(f"cannot read shebang of {relative}: {error}") from error
    return interpreter in _SHELL_INTERPRETERS


def _owner_index(owners: list[Owner]) -> dict[str, list[int]]:
    index: dict[str, list[int]] = {}
    for position, owner in enumerate(owners):
        for literal in owner.literals:
            index.setdefault(literal, []).append(position)
    return index


def _linked_pairs(index: dict[str, list[int]]) -> list[tuple[int, int]]:
    pairs: Counter[tuple[int, int]] = Counter()
    for positions in index.values():
        pairs.update(itertools.combinations(positions, 2))
    return [pair for pair, count in pairs.items() if count >= 2]


def _root(parent: list[int], item: int) -> int:
    while parent[item] != item:
        parent[item] = parent[parent[item]]
        item = parent[item]
    return item


def _union(parent: list[int], first: int, second: int) -> None:
    first_root, second_root = _root(parent, first), _root(parent, second)
    if first_root != second_root:
        parent[second_root] = first_root


def _groups(owners: list[Owner]) -> list[list[Owner]]:
    parent = list(range(len(owners)))
    for first, second in _linked_pairs(_owner_index(owners)):
        _union(parent, first, second)
    grouped: dict[int, list[Owner]] = {}
    for position, owner in enumerate(owners):
        grouped.setdefault(_root(parent, position), []).append(owner)
    return [group for group in grouped.values() if len(group) > 1]


def _shared_literals(group: list[Owner]) -> list[str]:
    counts = Counter(
        literal for owner in group for literal in owner.literals
    )
    return sorted(
        literal for literal, count in counts.items() if count >= 2
    )


def _owner_text(owner: Owner) -> str:
    return f"{owner.path}:{owner.start_line} {owner.name} ({owner.kind})"


def _owner_json(owner: Owner) -> dict[str, Any]:
    return {
        "path": owner.path,
        "line": owner.start_line,
        "name": owner.name,
        "kind": owner.kind,
        "literals": sorted(owner.literals),
    }


def _vsd_finding(group: list[Owner]) -> Finding:
    shared = _shared_literals(group)
    ordered = sorted(
        group, key=lambda owner: (owner.path, owner.start_line, owner.name)
    )
    subject = _VSD_HEADER.format(
        literals=", ".join(json.dumps(value) for value in shared),
        count=len(ordered),
        places=", ".join(_owner_text(owner) for owner in ordered),
    )
    first = ordered[0]
    return Finding(
        subject,
        1,
        f"{first.path}:{first.start_line}",
        {"literals": shared, "owners": [
            _owner_json(owner) for owner in ordered
        ]},
        tuple(
            Location(owner.path, owner.start_line, owner.end_line)
            for owner in ordered
        ),
    )


def _module_functions(
    tree: ast.Module,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _format_literals(tree: ast.Module) -> frozenset[str]:
    literals: set[str] = set()
    for _name, _statement, values in _declared_tables(tree):
        literals.update(values)
    return frozenset(literals)


def _all_functions(tree: ast.Module):
    return (
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _module_call(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.AST] | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return None
    callee = functions.get(node.func.id)
    if callee is None or not node.args:
        return None
    return callee, node.args[0]


def _pair_calls(
    calls: list[tuple[ast.AST, ast.AST]]
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    pairs: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    first, argument = calls[0]
    for callee, other_argument in calls[1:]:
        if callee is not first and ast.dump(other_argument) == ast.dump(argument):
            pairs.append((first, callee, argument))
        first, argument = callee, other_argument
    return pairs


def _or_chain(
    node: ast.BoolOp,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    calls = [_module_call(value, functions) for value in node.values]
    if any(call is None for call in calls):
        return []
    return _pair_calls(calls)


def _scope_nodes(node: ast.AST, kinds: Any) -> list[Any]:
    return [
        child for child in _scope_walk(node.body)
        if isinstance(child, kinds)
    ]


def _or_chains(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    return [
        chain
        for child in _scope_nodes(node, ast.BoolOp)
        if isinstance(child.op, ast.Or)
        for chain in _or_chain(child, functions)
    ]


def _assign_calls(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[int, str, tuple[ast.AST, ast.AST]]]:
    found: list[tuple[int, str, tuple[ast.AST, ast.AST]]] = []
    for child in _scope_walk(node.body):
        if (
            isinstance(child, ast.Assign)
            and len(child.targets) == 1
            and isinstance(child.targets[0], ast.Name)
        ):
            call = _module_call(child.value, functions)
            if call is not None:
                found.append((child.lineno, child.targets[0].id, call))
    return found


def _guards(node: ast.AST) -> list[tuple[ast.If, str]]:
    found: list[tuple[ast.If, str]] = []
    for child in _scope_walk(node.body):
        if not isinstance(child, ast.If):
            continue
        match child.test:
            case ast.UnaryOp(op=ast.Not(), operand=ast.Name(id=name)):
                found.append((child, name))
            case ast.Compare(
                ops=[ast.Is()],
                left=ast.Name(id=name),
                comparators=[ast.Constant(value=None)],
            ):
                found.append((child, name))
    return found


def _is_other_call(
    callee: ast.AST,
    argument: ast.AST,
    other: ast.AST,
    other_argument: ast.AST,
) -> bool:
    return (
        callee is not other
        and ast.dump(other_argument) == ast.dump(argument)
    )


def _handler_calls(
    nodes: list[ast.AST],
    callee: ast.AST,
    argument: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    found: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for other, other_argument in _body_calls(nodes, functions):
        if _is_other_call(callee, argument, other, other_argument):
            found.append((callee, other, argument))
    return found


def _guard_chains(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    assignments = _assign_calls(node, functions)
    guards = _guards(node)
    chains: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for line, name, (callee, argument) in assignments:
        for guard, guard_name in guards:
            if guard_name == name and guard.lineno > line:
                chains.extend(_handler_calls(
                    guard.body, callee, argument, functions
                ))
    return chains


def _body_calls(
    nodes: list[ast.AST],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST]]:
    found: list[tuple[ast.AST, ast.AST]] = []
    for child in _scope_walk(nodes):
        if not isinstance(child, ast.Call):
            continue
        call = _module_call(child, functions)
        if call is not None:
            found.append(call)
    return found


def _handler_pairs(
    body: list[tuple[ast.AST, ast.AST]],
    handled: list[tuple[ast.AST, ast.AST]],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    chains: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for callee, argument in body:
        for other, other_argument in handled:
            if _is_other_call(callee, argument, other, other_argument):
                chains.append((callee, other, argument))
    return chains


def _try_chain(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    body = _body_calls(node.body, functions)
    chains: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for handler in node.handlers:
        chains.extend(_handler_pairs(
            body, _body_calls(handler.body, functions)
        ))
    return chains


def _try_chains(
    node: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    chains: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for child in _scope_nodes(node, (ast.Try, ast.TryStar)):
        chains.extend(_try_chain(child, functions))
    return chains


def _same_annotation(first: ast.AST, second: ast.AST) -> bool:
    return (
        first.returns is not None
        and second.returns is not None
        and ast.dump(first.returns) == ast.dump(second.returns)
    )


def _name_token(first: str, second: str, formats: frozenset[str]) -> bool:
    return bool((set(first.split("_")) ^ set(second.split("_"))) & formats)


def _caller_span(relative: str, node: ast.AST) -> Owner:
    return Owner(
        relative,
        node.name,
        KIND_FUNCTION,
        _start_line(node),
        node.end_lineno or node.lineno,
        frozenset(),
    )


def _trial_finding(
    span: Owner,
    first: ast.AST,
    second: ast.AST,
    argument: ast.AST,
    formats: frozenset[str],
) -> Finding | None:
    if not _same_annotation(first, second) or not _name_token(
        first.name, second.name, formats
    ):
        return None
    argument_text = ast.unparse(argument)
    subject = (
        f"TRIAL variant-dispatch: {span.path}:{span.start_line} {span.name} "
        f"tries {first.name} then {second.name} on {argument_text}; select "
        "the reader from the table that names the formats, by the record's "
        "declared format, instead of trying each."
    )
    return Finding(
        subject,
        1,
        f"{span.path}:{span.start_line}",
        {
            "caller": span.name,
            "first": first.name,
            "second": second.name,
            "argument": argument_text,
        },
        (Location(span.path, span.start_line, span.end_line),),
    )


def _python_trials(
    relative: str, source: str
) -> list[tuple[Finding, Owner]]:
    tree = _parse_tree(relative, source)
    formats = _format_literals(tree)
    if not formats:
        return []
    functions = _module_functions(tree)
    trials: list[tuple[Finding, Owner]] = []
    for node in _all_functions(tree):
        span = _caller_span(relative, node)
        seen: set[tuple[tuple[str, str], str]] = set()
        chains = [
            *_or_chains(node, functions),
            *_guard_chains(node, functions),
            *_try_chains(node, functions),
        ]
        for first, second, argument in chains:
            key = (
                tuple(sorted((first.name, second.name))),
                ast.dump(argument),
            )
            if key in seen:
                continue
            seen.add(key)
            finding = _trial_finding(
                span, first, second, argument, formats
            )
            if finding is not None:
                trials.append((finding, span))
    return trials


def _selected(context: Any) -> list[str]:
    from .checks import _select_files

    selected, _names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    return selected


def _changed(
    spec: VariantSpec, diff: Any, candidate: Candidate
) -> bool:
    return any(
        owner.kind != KIND_TOP_LEVEL and _touched(spec, diff, owner)
        for owner in candidate.owners
    )


def _candidate_findings(
    owners: list[Owner], trials: list[tuple[Finding, Owner]]
) -> list[Candidate]:
    candidates = [
        Candidate(_vsd_finding(group), tuple(group))
        for group in _groups(owners)
    ]
    candidates.extend(
        Candidate(finding, (span,)) for finding, span in trials
    )
    return candidates


def _changed_candidates(
    spec: VariantSpec, diff: Any, candidates: list[Candidate]
) -> list[Candidate]:
    return [
        candidate for candidate in candidates
        if _changed(spec, diff, candidate)
    ]


def _measure(
    context: Any,
) -> tuple[list[Candidate], int, DiffBase | None]:
    spec = context.check.spec
    diff = None
    base = None
    if spec.scope == "changed":
        base = diff_base(
            context.root, spec.base, resolved=context.base_override
        )
        diff = _diff_lines(context.root, base.commit)
    owners: list[Owner] = []
    trials: list[tuple[Finding, Owner]] = []
    for relative in _selected(context):
        if _is_python_program(context.root, relative):
            source = _read_source(context.root, relative)
            owners.extend(_python_owners(relative, source))
            trials.extend(_python_trials(relative, source))
        elif _is_shell_program(context.root, relative):
            owners.extend(_shell_owners(
                relative, _read_source(context.root, relative)
            ))
    owners.sort(key=lambda owner: (owner.path, owner.start_line, owner.name))
    candidates = _candidate_findings(owners, trials)
    if diff is not None:
        candidates = _changed_candidates(spec, diff, candidates)
    return candidates, len(owners), base


def _measurement(count: int, base: DiffBase | None) -> dict[str, Any]:
    measurement: dict[str, Any] = {"owners": count}
    if base is not None:
        measurement["base"] = base.measurement()
    return measurement


def _ratchet_outcome(
    prefix: str,
    check: Any,
    start: float,
    ratchet: Any,
    failure: str | None,
    measurement: dict[str, Any],
) -> Any:
    from .checks import _ratchet_result

    if ratchet is None:
        return _ratchet_result(
            check, start, failure, reason=failure, measurement=measurement
        )
    if ratchet.satisfied:
        print(
            f"{prefix}: {measurement['owners']} owners measured", flush=True
        )
    return _ratchet_result(
        check, start, ratchet.outcome, ratchet=ratchet,
        measurement=measurement,
    )


def _finish(
    context: Any, check: Any, start: float, measured: tuple[Any, int, Any]
) -> Any:
    from .checks import _evaluate_ratchet

    candidates, count, base = measured
    findings = [candidate.finding for candidate in candidates]
    findings.sort(key=lambda finding: finding.subject)
    domain = Domain.of_subjects(
        [finding.subject for finding in findings],
        "the measured owners and vocabularies",
    )
    ratchet, failure = _evaluate_ratchet(
        findings, [], check, context.prefix, domain
    )
    return _ratchet_outcome(
        context.prefix, check, start, ratchet, failure,
        _measurement(count, base),
    )


def _run_variant_dispatch(context: Any) -> Any:
    from .checks import _ratchet_error

    check = context.check
    start = time.monotonic()
    try:
        measured = _measure(context)
    except GateError as error:
        result = _ratchet_error(check, start, context.prefix, error)
        result.configuration_error = True
        return result
    mark_step("variant-dispatch rules")
    return _finish(context, check, start, measured)
