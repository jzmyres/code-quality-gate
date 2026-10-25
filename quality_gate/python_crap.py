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
    node: ast.FunctionDef | ast.AsyncFunctionDef
    start_line: int
    end_line: int
    cc: int


@dataclass
class CrapMeasurement:
    findings: list[Finding]
    failures: list[str]


def _bool_operands(node: ast.BoolOp) -> int:
    return max(0, len(node.values) - 1)


def _comprehension(node: ast.comprehension) -> int:
    return 1 + len(node.ifs)


def _match_case(node: ast.match_case) -> int:
    pattern = node.pattern
    if (
        node.guard is None
        and isinstance(pattern, ast.MatchAs)
        and pattern.pattern is None
        and pattern.name is None
    ):
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


def _collect_functions(
    nodes: list[ast.AST],
    prefix: str,
    path: str,
    found: list[MeasuredFunction],
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = (
                node.decorator_list[0].lineno
                if node.decorator_list
                else node.lineno
            )
            found.append(
                MeasuredFunction(
                    identity=f"{path}:{prefix}{node.name}",
                    path=path,
                    name=f"{prefix}{node.name}",
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


def collect_functions(
    relative: str, source: str
) -> list[MeasuredFunction]:
    tree = ast.parse(source, filename=relative)
    found: list[MeasuredFunction] = []
    _collect_functions([tree], "", relative, found)
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
) -> tuple[float, dict[str, Any]] | None:
    # The def and decorator lines run when the module is imported, not when the function is called, so
    # only the body's statements measure whether the tests exercised the function.
    body_start = function.node.body[0].lineno
    lines = [
        line
        for line in statements
        if body_start <= line <= function.end_line
    ]
    if not lines:
        return None
    missing_set = set(missing)
    executed = sum(1 for line in lines if line not in missing_set)
    coverage = executed / len(lines)
    crap = function.cc**2 * (1 - coverage) ** 3 + function.cc
    measurement = {
        "cc": function.cc,
        "statements": len(lines),
        "executed": executed,
        "excluded_lines": sorted(
            line
            for line in excluded
            if body_start <= line <= function.end_line
        ),
    }
    return crap, measurement


def measure_crap(
    root: Path, selected: list[str], evidence: Path
) -> CrapMeasurement:
    """Measure every non-nested function in SELECTED using combined data."""
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
    cover = coverage.Coverage(data_file=str(evidence), config_file=False)
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
                measured = _measure_one(
                    function, statements, excluded, missing
                )
                if measured is None:
                    failures.append(
                        f"{function.identity}: unmeasured (no coverage "
                        f"statements between {function.path}:"
                        f"{function.start_line} and {function.end_line})"
                    )
                    continue
                value, measurement = measured
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
