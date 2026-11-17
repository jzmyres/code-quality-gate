"""Variant dispatch: one vocabulary declared once, and one reader per format.

Every selected Python file yields owners: a Python function or a module-level
table.  Each owner's set is the string literals it treats as a vocabulary.  Two
owners that share at least two literals belong to one finding, whose remedy is
one declared table read through one path.  A second rule reports a function
that guesses a format by trying two same-annotation readers in a fallback
chain.  A missing or invalid input is a configuration error, never a skipped
rule, and the check has no baseline or exemption list.
"""
from __future__ import annotations

import ast
import itertools
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .files import DiffBase, diff_base
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


def _letter_literals(words: list[str]) -> frozenset[str]:
    return frozenset(word for word in words if _has_letter(word))


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


def _dict_key_literals(
    display: ast.Dict, *, all_strings: bool, minimum: int
) -> frozenset[str] | None:
    keys: list[str] = []
    for key in display.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.append(key.value)
        elif all_strings:
            return None
    if len(keys) < minimum:
        return None
    return _letter_literals(keys)


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
    return _letter_literals(words)


def _declared_literals(node: ast.AST) -> frozenset[str] | None:
    if isinstance(node, ast.Dict):
        return _dict_key_literals(node, all_strings=True, minimum=2)
    if (
        isinstance(node, ast.Call)
        and _called_name(node) == "frozenset"
        and len(node.args) == 1
        and not node.keywords
    ):
        return _word_display(node.args[0], 2)
    return _word_display(node, 2)


def _table_names(statement: ast.AST) -> list[str]:
    targets = (
        statement.targets
        if isinstance(statement, ast.Assign)
        else [statement.target]
        if isinstance(statement, ast.AnnAssign)
        else []
    )
    return [
        target.id for target in targets if isinstance(target, ast.Name)
    ]


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
        elif not _literal_flags(other)[0]:
            displays.append(literals)
        return True
    return False


def _compare_literals(
    node: ast.Compare,
    subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    operands = [node.left, *node.comparators]
    for index, operation in enumerate(node.ops):
        left, right = operands[index], operands[index + 1]
        if isinstance(operation, (ast.In, ast.NotIn)) and _display_sets(
            left, right, subjects, displays
        ):
            continue
        if isinstance(operation, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
            _add_literal(subjects, right, left)
            _add_literal(subjects, left, right)


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


def _match_into(
    node: ast.Match,
    _subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    literals: set[str] = set()
    for case in node.cases:
        literals.update(_pattern_literals(case.pattern))
    displays.append(frozenset(literals))


def _selection_into(
    node: ast.AST,
    _subjects: dict[str, set[str]],
    displays: list[frozenset[str]],
) -> None:
    display, key = _selection_parts(node)
    if display is None or key is None:
        return
    literals = (
        _dict_key_literals(display, all_strings=False, minimum=2)
        if isinstance(display, ast.Dict) and not _literal_flags(key)[0]
        else frozenset()
    )
    displays.append(literals or frozenset())


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
    for values in [*subjects.values(), *displays]:
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





def _linked_pairs(owners: list[Owner]) -> list[tuple[int, int]]:
    index: dict[str, list[int]] = {}
    for position, owner in enumerate(owners):
        for literal in owner.literals:
            index.setdefault(literal, []).append(position)
    pairs: Counter[tuple[int, int]] = Counter()
    for positions in index.values():
        pairs.update(itertools.combinations(positions, 2))
    return [pair for pair, count in pairs.items() if count >= 2]


def _root(parent: list[int], item: int) -> int:
    while parent[item] != item:
        parent[item] = parent[parent[item]]
        item = parent[item]
    return item


def _groups(owners: list[Owner]) -> list[list[Owner]]:
    parent = list(range(len(owners)))
    for first, second in _linked_pairs(owners):
        first_root, second_root = _root(parent, first), _root(parent, second)
        if first_root != second_root:
            parent[second_root] = first_root
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


def _vsd_finding(group: list[Owner]) -> Finding:
    shared = _shared_literals(group)
    ordered = sorted(
        group, key=lambda owner: (owner.path, owner.start_line, owner.name)
    )
    subject = _VSD_HEADER.format(
        literals=", ".join(json.dumps(value) for value in shared),
        count=len(ordered),
        places=", ".join(
            f"{owner.path}:{owner.start_line} {owner.name} ({owner.kind})"
            for owner in ordered
        ),
    )
    first = ordered[0]
    return Finding(
        subject,
        1,
        f"{first.path}:{first.start_line}",
        {"literals": shared, "owners": [
            {
                "path": owner.path,
                "line": owner.start_line,
                "name": owner.name,
                "kind": owner.kind,
                "literals": sorted(owner.literals),
            }
            for owner in ordered
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


def _same_call(
    callee: ast.AST, argument: ast.AST, other: ast.AST, other_argument: ast.AST
) -> bool:
    return callee is not other and ast.dump(other_argument) == ast.dump(argument)


def _matching_calls(
    first: tuple[ast.AST, ast.AST] | None,
    second: tuple[ast.AST, ast.AST] | None,
) -> tuple[ast.AST, ast.AST, ast.AST] | None:
    if first is None or second is None:
        return None
    (callee, argument), (other, other_argument) = first, second
    if not _same_call(callee, argument, other, other_argument):
        return None
    return callee, other, argument


def _or_chain(
    node: ast.BoolOp,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    if (
        not isinstance(node, ast.BoolOp)
        or not isinstance(node.op, ast.Or)
        or len(node.values) != 2
    ):
        return []
    pair = _matching_calls(
        _module_call(node.values[0], functions),
        _module_call(node.values[1], functions),
    )
    return [] if pair is None else [pair]


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _statement_list(value: Any) -> list[ast.stmt] | None:
    if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
        return value
    return None


def _child_blocks(value: Any):
    for item in value if isinstance(value, list) else [value]:
        if isinstance(item, ast.AST):
            yield from _blocks(item)


def _blocks(node: ast.AST):
    """The statement lists of one function scope, without nested functions."""
    for _field, value in ast.iter_fields(node):
        statements = _statement_list(value)
        if statements is None:
            yield from _child_blocks(value)
            continue
        yield statements
        for statement in statements:
            if not isinstance(statement, _SCOPE_NODES):
                yield from _blocks(statement)


def _assigned_call(
    statement: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[str, tuple[ast.AST, ast.AST]] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        call = _module_call(statement.value, functions)
        if call is not None:
            return statement.targets[0].id, call
    return None


def _returned_call(
    statement: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[ast.AST, ast.AST] | None:
    if not isinstance(statement, ast.Return) or statement.value is None:
        return None
    return _module_call(statement.value, functions)


def _guard_name(test: ast.AST) -> str | None:
    match test:
        case ast.UnaryOp(op=ast.Not(), operand=ast.Name(id=name)):
            return name
        case ast.Compare(
            ops=[ast.Is()],
            left=ast.Name(id=name),
            comparators=[ast.Constant(value=None)],
        ):
            return name
    return None


def _guard_body(guard: ast.AST) -> ast.stmt | None:
    if not isinstance(guard, ast.If) or guard.orelse or len(guard.body) != 1:
        return None
    return guard.body[0]


def _returns_name(statement: ast.AST, name: str) -> bool:
    return (
        isinstance(statement, ast.Return)
        and isinstance(statement.value, ast.Name)
        and statement.value.id == name
    )


def _guard_assignment(
    block: list[ast.stmt],
    index: int,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[str, tuple[ast.AST, ast.AST]] | None:
    found = _assigned_call(block[index], functions)
    if found is None or index + 2 >= len(block):
        return None
    return found


def _guard_fallback(
    statement: ast.stmt,
    name: str,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[ast.AST, ast.AST] | None:
    found = _assigned_call(statement, functions)
    if found is None or found[0] != name:
        return None
    return found[1]


def _guard_chain(
    block: list[ast.stmt],
    index: int,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    found = _guard_assignment(block, index, functions)
    if found is None:
        return []
    name, first = found
    guard, final = block[index + 1], block[index + 2]
    statement = _guard_body(guard)
    if statement is None or _guard_name(guard.test) != name:
        return []
    if not _returns_name(final, name):
        return []
    pair = _matching_calls(
        first, _guard_fallback(statement, name, functions)
    )
    return [] if pair is None else [pair]


def _single_return(
    body: list[ast.stmt],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[ast.AST, ast.AST] | None:
    if len(body) != 1:
        return None
    return _returned_call(body[0], functions)


def _single_handler(statement: ast.AST) -> ast.ExceptHandler | None:
    if not isinstance(statement, (ast.Try, ast.TryStar)):
        return None
    if (
        len(statement.handlers) != 1
        or statement.orelse
        or statement.finalbody
    ):
        return None
    return statement.handlers[0]


def _try_chain(
    statement: ast.AST,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    handler = _single_handler(statement)
    if handler is None:
        return []
    pair = _matching_calls(
        _single_return(statement.body, functions),
        _single_return(handler.body, functions),
    )
    return [] if pair is None else [pair]


def _chains(
    block: list[ast.stmt],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[ast.AST, ast.AST, ast.AST]]:
    chains: list[tuple[ast.AST, ast.AST, ast.AST]] = []
    for index, statement in enumerate(block):
        if isinstance(statement, ast.Return) and statement.value is not None:
            chains.extend(_or_chain(statement.value, functions))
        chains.extend(_guard_chain(block, index, functions))
        if isinstance(statement, (ast.Try, ast.TryStar)):
            chains.extend(_try_chain(statement, functions))
    return chains


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
    if (
        first.returns is None
        or second.returns is None
        or ast.dump(first.returns) != ast.dump(second.returns)
        or not (
            (set(first.name.split("_")) ^ set(second.name.split("_")))
            & formats
        )
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


def _new_trial(
    seen: set[tuple[tuple[str, str], str]],
    span: Owner,
    chain: tuple[ast.AST, ast.AST, ast.AST],
    formats: frozenset[str],
) -> Finding | None:
    first, second, argument = chain
    key = (
        tuple(sorted((first.name, second.name))),
        ast.dump(argument),
    )
    if key in seen:
        return None
    seen.add(key)
    return _trial_finding(span, first, second, argument, formats)


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
        for block in _blocks(node):
            for chain in _chains(block, functions):
                finding = _new_trial(seen, span, chain, formats)
                if finding is not None:
                    trials.append((finding, span))
    return trials



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
        if any(_touched(spec, diff, owner) for owner in candidate.owners)
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
    from .checks import _select_files

    selected, _names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    owners: list[Owner] = []
    trials: list[tuple[Finding, Owner]] = []
    for relative in selected:
        if _is_python_program(context.root, relative):
            source = _read_source(context.root, relative)
            owners.extend(_python_owners(relative, source))
            trials.extend(_python_trials(relative, source))
    owners.sort(key=lambda owner: (owner.path, owner.start_line, owner.name))
    candidates = _candidate_findings(owners, trials)
    if diff is not None:
        candidates = _changed_candidates(spec, diff, candidates)
    return candidates, len(owners), base


def _finish(
    context: Any, check: Any, start: float, measured: tuple[Any, int, Any]
) -> Any:
    from .checks import _evaluate_ratchet, _ratchet_result

    candidates, count, base = measured
    findings: list[Finding] = []
    subjects: list[str] = []
    for candidate in candidates:
        finding = candidate.finding
        findings.append(finding)
        subjects.append(finding.subject)
    findings.sort(key=lambda finding: finding.subject)
    domain = Domain.of_subjects(
        subjects, "the measured owners and vocabularies",
    )
    ratchet, failure = _evaluate_ratchet(
        findings, [], check, context.prefix, domain
    )
    measurement: dict[str, Any] = {"owners": count}
    if base is not None:
        measurement["base"] = base.measurement()
    if ratchet is None:
        return _ratchet_result(
            check, start, failure, reason=failure, measurement=measurement
        )
    if ratchet.satisfied:
        print(
            f"{context.prefix}: {measurement['owners']} owners measured",
            flush=True,
        )
    return _ratchet_result(
        check, start, ratchet.outcome, ratchet=ratchet,
        measurement=measurement,
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
