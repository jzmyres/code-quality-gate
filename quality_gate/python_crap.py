"""Python CRAP measurement: ast complexity joined with coverage line data.

Cyclomatic complexity starts at one, then adds the table counter's
result for each matching construct. The walk includes nested function
and lambda bodies in the enclosing function's score. Counters for
selections from named tables also receive the scope's boolean-keyed
tables.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .coverage_tool import coverage_config_data, import_coverage
from .policy import CheckDef, GateError, UnsupportedError
from .ratchet import Domain, Finding, Location
from .runner import Diagnostics, mark_step


if TYPE_CHECKING:
    from .adapters import ParsedSpec
    from .checks import CheckResult


@dataclass(frozen=True)
class PythonCrapSpec:
    requires: str


def _python_crap_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import _crap_spec

    return _crap_spec(raw, root, path, full_key, PythonCrapSpec, "python-lines/1")


@dataclass(frozen=True)
class MeasuredFunction:
    identity: str
    path: str
    name: str
    node: ast.AST
    start_line: int
    end_line: int
    cc: int
    lines: tuple[int, ...] | None = None

    @classmethod
    def from_node(
        cls,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        path: str,
        prefix: str,
        module_tables: dict[str, int] | None = None,
    ) -> MeasuredFunction:
        identity = _function_identity(node, prefix)
        return cls(
            identity=f"{path}:{identity}",
            path=path,
            name=identity,
            node=node,
            start_line=_start_line(node),
            end_line=node.end_lineno or node.lineno,
            cc=_function_complexity(node, module_tables),
        )


@dataclass
class CrapMeasurement:
    findings: list[Finding]
    failures: list[str]
    excluded_lines: dict[str, tuple[int, ...]] | None


@dataclass(frozen=True)
class _SubjectMeasurement:
    value: float
    cc: int
    statements: int
    executed: int
    excluded_lines: tuple[int, ...]


def _bool_operands(node: ast.BoolOp) -> int:
    return max(0, len(node.values) - 1)


def _comprehension(node: ast.comprehension) -> int:
    return 1 + len(node.ifs)


_CALLED_NAME_FIELDS = {ast.Name: "id", ast.Attribute: "attr"}


def _called_name(node: ast.Call) -> str | None:
    field = _CALLED_NAME_FIELDS.get(type(node.func))
    return getattr(node.func, field) if field is not None else None


def _literal_flags(node: ast.AST) -> tuple[bool, bool]:
    """Whether a node is a constant, and whether it is a repeatable literal."""
    if isinstance(node, (ast.Tuple, ast.List)):
        return False, True
    if isinstance(node, ast.Constant):
        return True, isinstance(node.value, str)
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
    ):
        constant, _sequence = _literal_flags(node.operand)
        return constant, False
    return False, False


def _display_elements(node: ast.AST) -> int:
    if not isinstance(node, (ast.Tuple, ast.List)):
        return 0
    total = 0
    pending = [node]
    while pending:
        display = pending.pop()
        for element in display.elts:
            if isinstance(element, ast.Starred) and isinstance(
                element.value, (ast.Tuple, ast.List)
            ):
                pending.append(element.value)
            else:
                total += 1
    return max(0, total - 1)


def _any_all_operands(node: ast.Call) -> int:
    if (
        _called_name(node) in ("any", "all")
        and (len(node.args), len(node.keywords)) == (1, 0)
    ):
        return _display_elements(node.args[0])
    return 0


def _display_selection(node: ast.Subscript) -> int:
    constant, _sequence = _literal_flags(node.slice)
    if constant:
        return 0
    if isinstance(node.value, ast.Dict):
        positions = _tuple_boolean_positions(node.value)
        if positions is not None:
            return positions
        return max(0, len(node.value.keys) - 1)
    return _display_elements(node.value)


def _getattr_default(node: ast.Call) -> int:
    return int(
        _called_name(node) == "getattr"
        and len(node.args) == 3
    )


def _dict_get(node: ast.Call) -> int:
    display = getattr(node.func, "value", None)
    if not isinstance(display, ast.Dict) or _called_name(node) != "get":
        return 0
    positions = _tuple_boolean_positions(display)
    keys = (
        positions
        if positions is not None
        else max(0, len(display.keys) - 1)
    )
    return keys + int(len(node.args) >= 2)


def _boolean_key(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, bool)
    if isinstance(node, ast.Tuple) and node.elts:
        return all(
            isinstance(element, ast.Constant)
            and isinstance(element.value, bool)
            for element in node.elts
        )
    return False


def _boolean_keys(node: ast.AST) -> int | None:
    if not isinstance(node, ast.Dict) or not node.keys:
        return None
    for key in node.keys:
        if key is None or not _boolean_key(key):
            return None
    return len(node.keys)


def _tuple_width(keys: list[ast.AST | None]) -> int | None:
    width: int | None = None
    for key in keys:
        elts = key.elts if isinstance(key, ast.Tuple) else None
        if not elts:
            return None
        if width not in (None, len(elts)):
            return None
        width = len(elts)
    return width


def _boolean_positions(
    keys: list[ast.AST | None], width: int
) -> int:
    count = 0
    for index in range(width):
        if all(
            isinstance(key.elts[index], ast.Constant)
            and isinstance(key.elts[index].value, bool)
            for key in keys
            if isinstance(key, ast.Tuple)
        ):
            count += 1
    return count


def _tuple_boolean_positions(node: ast.Dict) -> int | None:
    """Boolean positions in tuple keys of one length, or None if not tuples."""
    keys = node.keys
    width = _tuple_width(keys)
    if width is None or all(_boolean_key(key) for key in keys):
        return None
    return _boolean_positions(keys, width)


def _table_selection_count(node: ast.AST) -> int | None:
    """The selection count that keeps the existing keys-minus-one arithmetic."""
    keys = _boolean_keys(node)
    if keys is not None:
        return keys
    if not isinstance(node, ast.Dict):
        return None
    positions = _tuple_boolean_positions(node)
    return None if positions in (None, 0) else positions + 1


def _assignment_targets(statement: ast.AST) -> list[ast.Name]:
    if isinstance(statement, ast.Assign):
        return [
            target for target in statement.targets
            if isinstance(target, ast.Name)
        ]
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
    ):
        return [statement.target]
    return []


def _record_boolean_table(
    statement: ast.AST,
    tables: dict[str, int],
    valid: set[int],
    invalid: set[str],
) -> None:
    keys = (
        _table_selection_count(statement.value)
        if statement.value is not None else None
    )
    for target in _assignment_targets(statement):
        if keys is None:
            invalid.add(target.id)
        else:
            valid.add(id(target))
            tables[target.id] = max(tables.get(target.id, 0), keys)


_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _scope_walk(node: ast.AST):
    """A node and its own scope, without a nested function, class or comprehension."""
    yield node
    if isinstance(node, _SCOPES):
        return
    for child in ast.iter_child_nodes(node):
        yield from _scope_walk(child)


def _collect_boolean_tables(
    node: ast.AST,
    tables: dict[str, int],
    valid: set[int],
    invalid: set[str],
    walk: Any,
) -> None:
    for child in walk(node):
        if isinstance(child, (ast.Assign, ast.AnnAssign)):
            _record_boolean_table(child, tables, valid, invalid)


def _record_rebindings(
    node: ast.AST, valid: set[int], invalid: set[str], walk: Any
) -> None:
    for child in walk(node):
        if (
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Store)
            and id(child) not in valid
        ):
            invalid.add(child.id)


def _boolean_tables(
    source: ast.AST | list[ast.AST], *, scoped: bool = False
) -> dict[str, int]:
    """The names bound in one scope to a dict display keyed by booleans."""
    roots = [source] if isinstance(source, ast.AST) else source
    walk = _scope_walk if scoped else ast.walk
    tables: dict[str, int] = {}
    valid: set[int] = set()
    invalid: set[str] = set()
    for root in roots:
        _collect_boolean_tables(root, tables, valid, invalid, walk)
        _record_rebindings(root, valid, invalid, walk)
    return {
        name: count
        for name, count in tables.items()
        if name not in invalid
    }


def _named_receiver(display: ast.AST, tables: dict[str, int]) -> int:
    if not isinstance(display, ast.Name):
        return -1
    return tables.get(display.id, -1)


def _named_selection(node: ast.Subscript, tables: dict[str, int]) -> int:
    keys = _named_receiver(node.value, tables)
    if keys < 0 or _literal_flags(node.slice)[0]:
        return 0
    return max(0, keys - 1)


def _named_get(node: ast.Call, tables: dict[str, int]) -> int:
    if (
        not isinstance(node.func, ast.Attribute)
        or node.func.attr != "get"
        or not node.args
    ):
        return 0
    keys = _named_receiver(node.func.value, tables)
    if keys < 0 or _literal_flags(node.args[0])[0]:
        return 0
    return max(0, keys - 1) + int(len(node.args) >= 2)


_LOOP_CALL_COUNTS = {
    "map": 1,
    "filter": 2,
    "filterfalse": 2,
    "dropwhile": 2,
    "takewhile": 2,
}


def _loop_call(node: ast.Call) -> int:
    return _LOOP_CALL_COUNTS.get(_called_name(node) or "", 0)


def _next_default(node: ast.Call) -> int:
    return int((_called_name(node), len(node.args)) == ("next", 2))


def _repetition(node: ast.BinOp) -> int:
    if not isinstance(node.op, ast.Mult):
        return 0
    left_constant, left_sequence = _literal_flags(node.left)
    right_constant, right_sequence = _literal_flags(node.right)
    return min(
        1,
        int(left_sequence and not right_constant)
        + int(right_sequence and not left_constant),
    )


def _irrefutable(pattern: ast.AST) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable(item) for item in pattern.patterns)
    return False


def _match_case(node: ast.match_case) -> int:
    if node.guard is None and _irrefutable(node.pattern):
        return 0
    return 1


CC_RULES: tuple[
    tuple[type[ast.AST], Callable[[Any], int]], ...
] = (
    (ast.If, lambda node: 1),
    (ast.IfExp, lambda node: 1),
    (ast.For, lambda node: 1),
    (ast.AsyncFor, lambda node: 1),
    (ast.While, lambda node: 1),
    (ast.comprehension, _comprehension),
    (ast.ExceptHandler, lambda node: 1),
    (ast.match_case, _match_case),
    (ast.BoolOp, _bool_operands),
    (ast.Call, _any_all_operands),
    (ast.Call, _getattr_default),
    (ast.Call, _dict_get),
    (ast.Call, _loop_call),
    (ast.Call, _next_default),
    (ast.Subscript, _display_selection),
    (ast.BinOp, _repetition),
)

_BOUND_RULES: tuple[
    tuple[type[ast.AST], Callable[[Any, dict[str, int]], int]], ...
] = (
    (ast.Subscript, _named_selection),
    (ast.Call, _named_get),
)


def _count_rules(nodes: Any, tables: dict[str, int]) -> int:
    total = 1
    for child in nodes:
        for kind, counter in CC_RULES:
            if isinstance(child, kind):
                total += counter(child)
        for kind, counter in _BOUND_RULES:
            if isinstance(child, kind):
                total += counter(child, tables)
    return total


def cyclomatic_complexity(
    node: ast.AST, tables: dict[str, int] | None = None
) -> int:
    if tables is None:
        tables = _boolean_tables(node)
    return _count_rules(ast.walk(node), tables)


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _imported_from(
    statement: ast.ImportFrom, modules: tuple[str, ...], name: str
) -> set[str]:
    if statement.module not in modules:
        return set()
    return {
        alias.asname or alias.name
        for alias in statement.names
        if alias.name == name
    }


def _imported_modules(
    statement: ast.Import, names: tuple[str, ...]
) -> set[str]:
    return {
        alias.asname or alias.name
        for alias in statement.names
        if alias.name in names
    }


def _typing_overload(tree: ast.Module) -> tuple[set[str], set[str]]:
    """The names bound to overload and the module aliases of typing."""
    names: set[str] = set()
    modules: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            names.update(
                _imported_from(
                    statement, ("typing", "typing_extensions"), "overload"
                )
            )
        elif isinstance(statement, ast.Import):
            modules.update(
                _imported_modules(
                    statement, ("typing", "typing_extensions")
                )
            )
    return names, modules


def _overload_decorator(
    decorator: ast.AST, names: set[str], modules: set[str]
) -> bool:
    if isinstance(decorator, ast.Name):
        return decorator.id in names
    return (
        isinstance(decorator, ast.Attribute)
        and decorator.attr == "overload"
        and isinstance(decorator.value, ast.Name)
        and decorator.value.id in modules
    )


def _ellipsis_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return (
        len(node.body) == 1
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and node.body[0].value.value is Ellipsis
    )


def _is_overload(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    names: set[str],
    modules: set[str],
) -> bool:
    return _ellipsis_body(node) and any(
        _overload_decorator(decorator, names, modules)
        for decorator in node.decorator_list
    )


def _function_identity(
    node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str
) -> str:
    for decorator in node.decorator_list:
        if (
            isinstance(decorator, ast.Attribute)
            and decorator.attr in ("setter", "deleter")
        ):
            base = _decorator_name(decorator.value) or node.name
            return f"{prefix}{base}.{decorator.attr}"
    return f"{prefix}{node.name}"


def _start_line(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> int:
    if node.decorator_list:
        return node.decorator_list[0].lineno
    return node.lineno


def _function_complexity(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_tables: dict[str, int] | None = None,
) -> int:
    """Count the executable body of a function.

    Defaults, decorators and annotations run at definition time and belong
    to the enclosing owner.
    """
    tables = _boolean_tables(node.body)
    for name, count in _boolean_tables(node.body, scoped=True).items():
        tables[name] = max(tables.get(name, 0), count)
    if module_tables:
        for name, count in module_tables.items():
            tables[name] = max(tables.get(name, 0), count)
    return cyclomatic_complexity(
        ast.Module(body=node.body, type_ignores=[]), tables
    )


def _collect_functions(
    nodes: list[ast.AST],
    prefix: str,
    path: str,
    found: list[MeasuredFunction],
    overload_names: set[str],
    typing_modules: set[str],
    module_tables: dict[str, int],
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_overload(node, overload_names, typing_modules):
                continue
            found.append(MeasuredFunction.from_node(
                node, path, prefix, module_tables
            ))
            continue
        if isinstance(node, ast.ClassDef):
            _collect_functions(
                node.body,
                f"{prefix}{node.name}.",
                path,
                found,
                overload_names,
                typing_modules,
                module_tables,
            )
            continue
        for child in ast.iter_child_nodes(node):
            _collect_functions(
                [child],
                prefix,
                path,
                found,
                overload_names,
                typing_modules,
                module_tables,
            )


def _argument_defaults(arguments: ast.arguments) -> list[ast.AST]:
    return [
        default
        for default in [*arguments.defaults, *arguments.kw_defaults]
        if default is not None
    ]


def _argument_annotations(arguments: ast.arguments) -> list[ast.AST]:
    annotations: list[ast.AST] = []
    for argument in [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
        arguments.vararg,
        arguments.kwarg,
    ]:
        if argument is not None and argument.annotation is not None:
            annotations.append(argument.annotation)
    return annotations


def _outside_children(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        children = [*node.decorator_list]
        children.extend(_argument_defaults(node.args))
        children.extend(_argument_annotations(node.args))
        if node.returns is not None:
            children.append(node.returns)
        return children
    if isinstance(node, ast.Lambda):
        return _argument_defaults(node.args)
    if isinstance(node, ast.ClassDef):
        return [
            *node.decorator_list,
            *node.bases,
            *node.keywords,
            *node.body,
        ]
    return list(ast.iter_child_nodes(node))


def _is_docstring(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _walk_outside(node: ast.AST):
    if _is_docstring(node):
        return
    yield node
    for child in _outside_children(node):
        yield from _walk_outside(child)


def _outside_nodes(tree: ast.Module) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    for statement in tree.body:
        nodes.extend(_walk_outside(statement))
    return nodes


def _node_lines(nodes: list[ast.AST]) -> list[int]:
    lines: set[int] = set()
    for node in nodes:
        line = getattr(node, "lineno", 0)
        if line > 0:
            lines.add(line)
    return sorted(lines)


def _last_end_line(nodes: list[ast.AST], default: int) -> int:
    ends: list[int] = []
    for node in nodes:
        node_end = getattr(node, "end_lineno", None)
        if node_end is not None:
            ends.append(node_end)
    if not ends:
        return default
    return max(ends)


def _module_subject(
    tree: ast.Module, relative: str, module_tables: dict[str, int]
) -> MeasuredFunction | None:
    nodes = _outside_nodes(tree)
    lines = _node_lines(nodes)
    if not lines:
        return None
    end = _last_end_line(nodes, lines[-1])
    return MeasuredFunction(
        identity=f"{relative}:<module>",
        path=relative,
        name="<module>",
        node=tree,
        start_line=lines[0],
        end_line=end,
        cc=_count_rules(nodes, module_tables),
        lines=tuple(lines),
    )


def _lambda_lines(node: ast.Lambda) -> tuple[int, ...]:
    """Measure a lambda on its own body lines.

    The declaration line runs at module import. The body runs when called.
    """
    return tuple(
        line
        for line in _node_lines(list(ast.walk(node.body)))
        if line > node.lineno
    )


def _lambda_subject(
    node: ast.Lambda, relative: str, module_tables: dict[str, int]
) -> MeasuredFunction | None:
    tables = _boolean_tables(node)
    for name, count in module_tables.items():
        tables[name] = max(tables.get(name, 0), count)
    cc = cyclomatic_complexity(node, tables)
    if cc == 1:
        return None
    return MeasuredFunction(
        identity=f"{relative}:<lambda@{node.lineno}>",
        path=relative,
        name=f"<lambda@{node.lineno}>",
        node=node,
        start_line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        cc=cc,
        lines=_lambda_lines(node),
    )


def _lambda_subjects(
    tree: ast.Module, relative: str, module_tables: dict[str, int]
) -> list[MeasuredFunction]:
    found: list[MeasuredFunction] = []
    for node in _outside_nodes(tree):
        if isinstance(node, ast.Lambda):
            subject = _lambda_subject(
                node, relative, module_tables
            )
            if subject is not None:
                found.append(subject)
    return found


def collect_functions(
    relative: str, source: str
) -> list[MeasuredFunction]:
    tree = ast.parse(source, filename=relative)
    overload_names, typing_modules = _typing_overload(tree)
    module_tables = _boolean_tables(tree.body, scoped=True)
    found: list[MeasuredFunction] = []
    _collect_functions(
        [tree], "", relative, found, overload_names, typing_modules,
        module_tables,
    )
    found.extend(_lambda_subjects(tree, relative, module_tables))
    module = _module_subject(tree, relative, module_tables)
    if module is not None:
        found.append(module)
    return sorted(found, key=lambda item: (item.start_line, item.identity))


def _duplicate_failures(functions: list[MeasuredFunction]) -> list[str]:
    first_seen: dict[str, MeasuredFunction] = {}
    failures: list[str] = []
    for function in functions:
        first = first_seen.get(function.identity)
        if first is None:
            first_seen[function.identity] = function
            continue
        failures.append(
            f"duplicate function identity {function.identity!r} at "
            f"{function.path}:{first.start_line} and "
            f"{function.path}:{function.start_line}"
        )
    return failures


def _lines_in(values: list[int], allowed: set[int]) -> list[int]:
    return [line for line in values if line in allowed]


def _lines_between(
    values: list[int], start: int, end: int
) -> list[int]:
    return [line for line in values if start <= line <= end]


def _executed_count(lines: list[int], missing: list[int]) -> int:
    missing_set = set(missing)
    return sum(1 for line in lines if line not in missing_set)


def _crap_result(
    function: MeasuredFunction,
    lines: list[int],
    excluded_lines: list[int],
    executed: int,
) -> tuple[_SubjectMeasurement | None, str | None]:
    if not lines:
        return None, "no coverage statements in the measured span"
    coverage = executed / len(lines)
    crap = function.cc**2 * (1 - coverage) ** 3 + function.cc
    return _SubjectMeasurement(crap, function.cc, len(lines), executed, tuple(sorted(excluded_lines))), None


def _measure_lambda(
    function: MeasuredFunction,
    excluded: list[int],
    executed_lines: list[int],
) -> tuple[_SubjectMeasurement | None, str | None]:
    lines = list(function.lines or ())
    if not lines:
        return (
            None,
            "lambda body shares the declaration line; put the body on its own "
            "line",
        )
    excluded_lines = _lines_in(excluded, set(lines))
    missing = [line for line in lines if line not in executed_lines]
    executed = _executed_count(lines, missing)
    return _crap_result(function, lines, excluded_lines, executed)


def _measure_one(
    function: MeasuredFunction,
    statements: list[int],
    excluded: list[int],
    missing: list[int],
    executed_lines: list[int],
) -> tuple[_SubjectMeasurement | None, str | None]:
    """Measure whether the tests exercised the function body.

    The definition and decorator lines run during import. Only the body's
    statements count toward coverage of the function.
    """
    if isinstance(function.node, ast.Lambda):
        return _measure_lambda(function, excluded, executed_lines)
    if function.lines is not None:
        owned = set(function.lines)
        lines = _lines_in(statements, owned)
        excluded_lines = _lines_in(excluded, owned)
    else:
        assert isinstance(
            function.node, (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        if function.node.body[0].lineno == function.node.lineno:
            return (
                None,
                "body shares the def line; put the body on its own line",
            )
        body_start = function.node.body[0].lineno
        lines = _lines_between(statements, body_start, function.end_line)
        excluded_lines = _lines_between(
            excluded, body_start, function.end_line
        )
    executed = _executed_count(lines, missing)
    return _crap_result(function, lines, excluded_lines, executed)


def _executed_lines(cover: Any, filename: str) -> list[int]:
    lines = cover.get_data().lines(filename)
    return lines if lines is not None else []


def _parse_selected(
    root: Path, selected: list[str]
) -> tuple[dict[str, tuple[str, list[MeasuredFunction]]], list[str]]:
    failures: list[str] = []
    parsed: dict[str, tuple[str, list[MeasuredFunction]]] = {}
    for relative in selected:
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise GateError(f"cannot read {relative}: {error}") from error
        try:
            functions = collect_functions(relative, source)
        except SyntaxError as error:
            raise GateError(
                f"cannot parse {relative}: {error}"
            ) from error
        parsed[relative] = (source, functions)
        failures.extend(_duplicate_failures(functions))
    return parsed, failures


def _analyse_functions(
    functions: list[MeasuredFunction], statements: list[int], excluded: list[int],
    missing: list[int], executed_lines: list[int], findings: list[Finding], failures: list[str],
    excluded_by_file: dict[str, set[int]],
) -> None:
    for function in functions:
        measurement, problem = _measure_one(
            function, statements, excluded, missing, executed_lines
        )
        if problem is not None:
            failures.append(
                f"{function.identity}: unmeasured ({problem} at "
                f"{function.path}:{function.start_line}-{function.end_line})"
            )
            continue
        assert measurement is not None
        excluded_by_file.setdefault(function.path, set()).update(measurement.excluded_lines)
        findings.append(Finding(
            function.identity, measurement.value,
            f"{function.path}:{function.start_line}-{function.end_line}",
            {
                "cc": measurement.cc,
                "statements": measurement.statements,
                "executed": measurement.executed,
                "excluded_lines": list(measurement.excluded_lines),
            },
            (Location(function.path, function.start_line, function.end_line),),
        ))


def _analyse_file(
    cover: Any, root: Path, relative: str, functions: list[MeasuredFunction],
    findings: list[Finding], failures: list[str],
    excluded_by_file: dict[str, set[int]],
) -> None:
    if not functions:
        return
    filename = str(root / relative)
    _filename, statements, excluded, missing, _formatted = cover.analysis2(filename)
    _analyse_functions(
        functions, statements, excluded, missing, _executed_lines(cover, filename), findings, failures,
        excluded_by_file,
    )


def _analyse_coverage(
    root: Path, selected: list[str], evidence: Path, settings: str,
    parsed: dict[str, tuple[str, list[MeasuredFunction]]], failures: list[str],
) -> tuple[list[Finding], dict[str, set[int]]]:
    if not evidence.is_file():
        raise GateError(f"combined coverage data is missing at {evidence}")
    coverage = import_coverage()
    cover = coverage.Coverage(
        config_file=coverage_config_data(settings, evidence)
    )
    findings: list[Finding] = []
    excluded_by_file: dict[str, set[int]] = {}
    try:
        cover.load()
        for relative in selected:
            _source, functions = parsed[relative]
            _analyse_file(cover, root, relative, functions, findings, failures, excluded_by_file)
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot analyse coverage data at {evidence}: {error}"
        ) from error
    return findings, excluded_by_file


def measure_crap(
    root: Path,
    selected: list[str],
    evidence: Path,
    settings: str,
) -> CrapMeasurement:
    """Measure every function and outside-function subject in SELECTED."""
    parsed, failures = _parse_selected(root, selected)
    if failures:
        return CrapMeasurement([], failures, None)
    findings, excluded_by_file = _analyse_coverage(root, selected, evidence, settings, parsed, failures)
    if failures:
        return CrapMeasurement([], failures, None)
    findings.sort(key=lambda item: item.subject)
    return CrapMeasurement(
        findings, [], {path: tuple(sorted(lines)) for path, lines in excluded_by_file.items()},
    )


def _file_present(path: Path | None) -> bool:
    return path is not None and path.is_file()


def _crap_missing_evidence(required: Any) -> str | None:
    if not _file_present(required.evidence_path):
        return "combined coverage data"
    data = required.adapter_data or {}
    if not _file_present(data.get("coverage_config")) or data.get("coverage_settings") is None:
        return "gate coverage configuration"
    return None


def _crap_required(
    prior: dict[str, Any],
    spec: Any,
    prefix: str,
) -> tuple[Path | None, str | None, Diagnostics | None, str | None]:
    required = prior.get(spec.requires)
    if required is None or required.outcome != "pass":
        message = f"coverage unreliable: {spec.requires} did not pass"
    else:
        missing = _crap_missing_evidence(required)
        if missing is None:
            return required.evidence_path, required.adapter_data["coverage_settings"], None, None
        message = (
            f"coverage unreliable: {spec.requires} produced no {missing}"
        )
    print(f"{prefix}: {message}", file=sys.stderr)
    return None, None, Diagnostics(error=message), message


def _crap_measure(
    root: Path,
    selected: list[str],
    evidence_path: Path | None,
    settings: str | None,
    check: CheckDef,
    start: float,
    prefix: str,
) -> tuple[CrapMeasurement | None, CheckResult | None]:
    from .checks import (
        _ratchet_error,
        _ratchet_result,
        _tail_diagnostics,
    )

    mark_step("CRAP analysis")
    try:
        measurement = measure_crap(
            root,
            selected,
            evidence_path,
            settings,
        )
    except UnsupportedError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return None, _ratchet_result(
            check,
            start,
            "unsupported",
            diagnostics=Diagnostics(error=str(error)),
            reason=str(error),
        )
    except GateError as error:
        return None, _ratchet_error(check, start, prefix, error)
    if not measurement.failures:
        return measurement, None
    for failure in measurement.failures:
        print(f"{prefix}: {failure}", file=sys.stderr)
    diagnostics = _tail_diagnostics(
        measurement.failures, argv=None, exit_code=1
    )
    return None, _ratchet_result(
        check,
        start,
        "fail",
        diagnostics=diagnostics,
        reason=diagnostics.output_tail,
    )


def _run_python_crap(context: Any) -> CheckResult:
    from .checks import (
        _adapter_selection,
        _class_text,
        _finish_crap_ratchet,
        _ratchet_result,
    )

    root, check = context.root, context.check
    prefix, prior = context.prefix, context.prior
    spec, start, selected, names = _adapter_selection(context)
    if not selected:
        reason = (
            f"no files selected (classes: {_class_text(names)}); "
            "zero inputs is not a pass"
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(check, start, "fail", reason=reason)

    mark_step("coverage evidence validation")
    evidence_path, settings, failure_diagnostics, message = _crap_required(
        prior, spec, prefix
    )
    if message is not None:
        return _ratchet_result(
            check,
            start,
            "unsupported",
            diagnostics=failure_diagnostics,
            reason=message,
        )

    measurement, failure = _crap_measure(
        root,
        selected,
        evidence_path,
        settings,
        check,
        start,
        prefix,
    )
    if failure is not None:
        return failure
    assert measurement is not None
    result = _finish_crap_ratchet(
        check,
        measurement.findings,
        prefix,
        start,
        lambda _entries: Domain.of_files(selected),
        ("functions", "function"),
    )
    if result.ratchet is not None:
        result.excluded_lines = measurement.excluded_lines
    return result
