"""Python CRAP measurement: ast complexity joined with coverage line data."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .coverage_tool import import_coverage
from .policy import GateError
from .ratchet import Finding


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


@dataclass
class CrapMeasurement:
    findings: list[Finding]
    failures: list[str]


def _bool_operands(node: ast.BoolOp) -> int:
    return max(0, len(node.values) - 1)


def _comprehension(node: ast.comprehension) -> int:
    return 1 + len(node.ifs)


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


# One data table for the cyclomatic-complexity constructs.  Every match adds
# the counter's result; the function's base is 1.  Nested function and lambda
# bodies are walked too, so they add to their enclosing function.
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
)


def cyclomatic_complexity(node: ast.AST) -> int:
    total = 1
    for child in ast.walk(node):
        for kind, counter in CC_RULES:
            if isinstance(child, kind):
                total += counter(child)
    return total


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _decorator_base(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_overload(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _decorator_name(decorator) == "overload"
        for decorator in node.decorator_list
    )


def _function_identity(
    node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str
) -> str:
    for decorator in node.decorator_list:
        suffix = _decorator_name(decorator)
        if suffix not in ("setter", "deleter"):
            continue
        assert isinstance(decorator, ast.Attribute)
        base = _decorator_base(decorator.value) or node.name
        return f"{prefix}{base}.{suffix}"
    return f"{prefix}{node.name}"


def _collect_functions(
    nodes: list[ast.AST],
    prefix: str,
    path: str,
    found: list[MeasuredFunction],
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_overload(node):
                continue
            start = (
                node.decorator_list[0].lineno
                if node.decorator_list
                else node.lineno
            )
            found.append(
                MeasuredFunction(
                    identity=f"{path}:{_function_identity(node, prefix)}",
                    path=path,
                    name=_function_identity(node, prefix),
                    node=node,
                    start_line=start,
                    end_line=node.end_lineno or node.lineno,
                    cc=cyclomatic_complexity(node),
                )
            )
            continue
        if isinstance(node, ast.ClassDef):
            _collect_functions(
                node.body, f"{prefix}{node.name}.", path, found
            )
            continue
        for child in ast.iter_child_nodes(node):
            _collect_functions([child], prefix, path, found)


def _walk_outside(node: ast.AST):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield node
        for decorator in node.decorator_list:
            yield from _walk_outside(decorator)
        arguments = node.args
        for default in [*arguments.defaults, *arguments.kw_defaults]:
            if default is not None:
                yield from _walk_outside(default)
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]:
            if argument is not None and argument.annotation is not None:
                yield from _walk_outside(argument.annotation)
        if node.returns is not None:
            yield from _walk_outside(node.returns)
        return
    if isinstance(node, ast.Lambda):
        yield node
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                yield from _walk_outside(default)
        return
    if isinstance(node, ast.ClassDef):
        yield node
        for decorator in node.decorator_list:
            yield from _walk_outside(decorator)
        for base in node.bases:
            yield from _walk_outside(base)
        for keyword in node.keywords:
            yield from _walk_outside(keyword)
        for statement in node.body:
            yield from _walk_outside(statement)
        return
    if (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _walk_outside(child)


def _outside_nodes(tree: ast.Module) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    for statement in tree.body:
        nodes.extend(_walk_outside(statement))
    return nodes


def _outside_complexity(nodes: list[ast.AST]) -> int:
    total = 1
    for node in nodes:
        for kind, counter in CC_RULES:
            if isinstance(node, kind):
                total += counter(node)
    return total


def _module_subject(
    tree: ast.Module, relative: str
) -> MeasuredFunction | None:
    nodes = _outside_nodes(tree)
    lines = sorted(
        {
            node.lineno
            for node in nodes
            if isinstance(node, ast.AST) and getattr(node, "lineno", 0) > 0
        }
    )
    if not lines:
        return None
    ends = [
        node.end_lineno
        for node in nodes
        if getattr(node, "end_lineno", None) is not None
    ]
    end = max(ends) if ends else lines[-1]
    return MeasuredFunction(
        identity=f"{relative}:<module>",
        path=relative,
        name="<module>",
        node=tree,
        start_line=lines[0],
        end_line=end,
        cc=_outside_complexity(nodes),
        lines=tuple(lines),
    )


def collect_functions(
    relative: str, source: str
) -> list[MeasuredFunction]:
    tree = ast.parse(source, filename=relative)
    found: list[MeasuredFunction] = []
    _collect_functions([tree], "", relative, found)
    module = _module_subject(tree, relative)
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


def _measure_one(
    function: MeasuredFunction,
    statements: list[int],
    excluded: list[int],
    missing: list[int],
) -> tuple[float | None, dict[str, Any] | None, str | None]:
    # The def and decorator lines run when the module is imported, not when the function is called, so
    # only the body's statements measure whether the tests exercised the function.
    if function.lines is not None:
        owned = set(function.lines)
        lines = [line for line in statements if line in owned]
        excluded_lines = [line for line in excluded if line in owned]
    else:
        assert isinstance(
            function.node, (ast.FunctionDef, ast.AsyncFunctionDef)
        )
        if function.node.body[0].lineno == function.node.lineno:
            return (
                None,
                None,
                "body shares the def line; put the body on its own line",
            )
        body_start = function.node.body[0].lineno
        lines = [
            line
            for line in statements
            if body_start <= line <= function.end_line
        ]
        excluded_lines = [
            line
            for line in excluded
            if body_start <= line <= function.end_line
        ]
    if not lines:
        return None, None, "no coverage statements in the measured span"
    missing_set = set(missing)
    executed = sum(1 for line in lines if line not in missing_set)
    coverage = executed / len(lines)
    crap = function.cc**2 * (1 - coverage) ** 3 + function.cc
    measurement = {
        "cc": function.cc,
        "statements": len(lines),
        "executed": executed,
        "excluded_lines": sorted(excluded_lines),
    }
    return crap, measurement, None


def measure_crap(
    root: Path,
    selected: list[str],
    evidence: Path,
    config_file: Path | None = None,
) -> CrapMeasurement:
    """Measure every function and outside-function subject in SELECTED."""
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
    if failures:
        return CrapMeasurement([], failures)

    if not evidence.is_file():
        raise GateError(f"combined coverage data is missing at {evidence}")
    coverage = import_coverage()
    cover = coverage.Coverage(
        data_file=str(evidence),
        config_file=str(config_file) if config_file is not None else False,
    )
    findings: list[Finding] = []
    try:
        cover.load()
        for relative in selected:
            _source, functions = parsed[relative]
            if not functions:
                continue
            _filename, statements, excluded, missing, _formatted = (
                cover.analysis2(str(root / relative))
            )
            for function in functions:
                value, measurement, problem = _measure_one(
                    function, statements, excluded, missing
                )
                if problem is not None:
                    failures.append(
                        f"{function.identity}: unmeasured ({problem} at "
                        f"{function.path}:{function.start_line}-"
                        f"{function.end_line})"
                    )
                    continue
                assert value is not None and measurement is not None
                findings.append(
                    Finding(
                        function.identity,
                        value,
                        f"{function.path}:{function.start_line}-"
                        f"{function.end_line}",
                        measurement,
                    )
                )
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot analyse coverage data at {evidence}: {error}"
        ) from error
    if failures:
        return CrapMeasurement([], failures)
    findings.sort(key=lambda item: item.subject)
    return CrapMeasurement(findings, [])
