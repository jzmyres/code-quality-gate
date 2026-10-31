"""Python CRAP measurement: ast complexity joined with coverage line data."""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .coverage_tool import coverage_config_data, import_coverage
from .policy import CheckDef, GateError, UnsupportedError
from .ratchet import Domain, Finding, Location
from .runner import Diagnostics, StepTimeout, analysis_step


@dataclass(frozen=True)
class PythonCrapSpec:
    requires: str


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
) -> int:
    # Defaults, decorators and annotations run at definition time and belong
    # to the enclosing owner, so only the executable body counts here.
    return cyclomatic_complexity(
        ast.Module(body=node.body, type_ignores=[])
    )


def _collect_functions(
    nodes: list[ast.AST],
    prefix: str,
    path: str,
    found: list[MeasuredFunction],
    overload_names: set[str],
    typing_modules: set[str],
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_overload(node, overload_names, typing_modules):
                continue
            start = _start_line(node)
            found.append(
                MeasuredFunction(
                    identity=f"{path}:{_function_identity(node, prefix)}",
                    path=path,
                    name=_function_identity(node, prefix),
                    node=node,
                    start_line=start,
                    end_line=node.end_lineno or node.lineno,
                    cc=_function_complexity(node),
                )
            )
            continue
        if isinstance(node, ast.ClassDef):
            _collect_functions(
                node.body,
                f"{prefix}{node.name}.",
                path,
                found,
                overload_names,
                typing_modules,
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


def _function_outside_children(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    children = [*node.decorator_list]
    children.extend(_argument_defaults(node.args))
    children.extend(_argument_annotations(node.args))
    if node.returns is not None:
        children.append(node.returns)
    return children


def _class_outside_children(node: ast.ClassDef) -> list[ast.AST]:
    return [
        *node.decorator_list,
        *node.bases,
        *node.keywords,
        *node.body,
    ]


def _outside_children(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _function_outside_children(node)
    if isinstance(node, ast.Lambda):
        return _argument_defaults(node.args)
    if isinstance(node, ast.ClassDef):
        return _class_outside_children(node)
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


def _outside_complexity(nodes: list[ast.AST]) -> int:
    total = 1
    for node in nodes:
        for kind, counter in CC_RULES:
            if isinstance(node, kind):
                total += counter(node)
    return total


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
    tree: ast.Module, relative: str
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
        cc=_outside_complexity(nodes),
        lines=tuple(lines),
    )


def _lambda_lines(node: ast.Lambda) -> tuple[int, ...]:
    # The declaration line only runs when the module is imported; the body
    # runs when the lambda is called, so it measures on its own lines.
    return tuple(
        line
        for line in _node_lines(list(ast.walk(node.body)))
        if line > node.lineno
    )


def _lambda_subject(
    node: ast.Lambda, relative: str
) -> MeasuredFunction | None:
    cc = cyclomatic_complexity(node)
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
    tree: ast.Module, relative: str
) -> list[MeasuredFunction]:
    found: list[MeasuredFunction] = []
    for node in _outside_nodes(tree):
        if isinstance(node, ast.Lambda):
            subject = _lambda_subject(node, relative)
            if subject is not None:
                found.append(subject)
    return found


def collect_functions(
    relative: str, source: str
) -> list[MeasuredFunction]:
    tree = ast.parse(source, filename=relative)
    overload_names, typing_modules = _typing_overload(tree)
    found: list[MeasuredFunction] = []
    _collect_functions(
        [tree], "", relative, found, overload_names, typing_modules
    )
    found.extend(_lambda_subjects(tree, relative))
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
) -> tuple[float | None, dict[str, Any] | None, str | None]:
    if not lines:
        return None, None, "no coverage statements in the measured span"
    coverage = executed / len(lines)
    crap = function.cc**2 * (1 - coverage) ** 3 + function.cc
    measurement = {
        "cc": function.cc,
        "statements": len(lines),
        "executed": executed,
        "excluded_lines": sorted(excluded_lines),
    }
    return crap, measurement, None


def _measure_lambda(
    function: MeasuredFunction,
    excluded: list[int],
    executed_lines: list[int],
) -> tuple[float | None, dict[str, Any] | None, str | None]:
    lines = list(function.lines or ())
    if not lines:
        return (
            None,
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
) -> tuple[float | None, dict[str, Any] | None, str | None]:
    # The def and decorator lines run when the module is imported, not when the function is called, so
    # only the body's statements measure whether the tests exercised the function.
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
) -> None:
    for function in functions:
        value, measurement, problem = _measure_one(
            function, statements, excluded, missing, executed_lines
        )
        if problem is not None:
            failures.append(
                f"{function.identity}: unmeasured ({problem} at "
                f"{function.path}:{function.start_line}-{function.end_line})"
            )
            continue
        assert value is not None and measurement is not None
        findings.append(Finding(
            function.identity, value, f"{function.path}:{function.start_line}-{function.end_line}",
            measurement, (Location(function.path, function.start_line, function.end_line),),
        ))


def _analyse_file(
    cover: Any, root: Path, relative: str, functions: list[MeasuredFunction],
    findings: list[Finding], failures: list[str],
) -> None:
    if not functions:
        return
    filename = str(root / relative)
    _filename, statements, excluded, missing, _formatted = cover.analysis2(filename)
    _analyse_functions(
        functions, statements, excluded, missing, _executed_lines(cover, filename), findings, failures,
    )


def _analyse_coverage(
    root: Path, selected: list[str], evidence: Path, settings: str,
    parsed: dict[str, tuple[str, list[MeasuredFunction]]], failures: list[str],
) -> list[Finding]:
    if not evidence.is_file():
        raise GateError(f"combined coverage data is missing at {evidence}")
    coverage = import_coverage()
    cover = coverage.Coverage(
        config_file=coverage_config_data(settings, evidence)
    )
    findings: list[Finding] = []
    try:
        cover.load()
        for relative in selected:
            _source, functions = parsed[relative]
            _analyse_file(cover, root, relative, functions, findings, failures)
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot analyse coverage data at {evidence}: {error}"
        ) from error
    return findings


def measure_crap(
    root: Path,
    selected: list[str],
    evidence: Path,
    settings: str,
) -> CrapMeasurement:
    """Measure every function and outside-function subject in SELECTED."""
    parsed, failures = _parse_selected(root, selected)
    if failures:
        return CrapMeasurement([], failures)
    findings = _analyse_coverage(root, selected, evidence, settings, parsed, failures)
    if failures:
        return CrapMeasurement([], failures)
    findings.sort(key=lambda item: item.subject)
    return CrapMeasurement(findings, [])


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
) -> tuple[Any | None, Any | None]:
    from .checks import RATCHET_BUDGET_SECONDS, _budget_detail, _ratchet_error, _ratchet_result

    try:
        measurement = analysis_step(
            "CRAP analysis", measure_crap,
            root,
            selected,
            evidence_path,
            settings,
            deadline=start + RATCHET_BUDGET_SECONDS,
        )
    except StepTimeout:
        reason = _budget_detail(
            "CRAP analysis exceeded the remaining budget", start, RATCHET_BUDGET_SECONDS
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return None, _ratchet_result(
            check, start, "fail", execution="budget", reason=reason
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
    return measurement, None


def _run_python_crap(context: Any) -> Any:
    from .checks import (
        _adapter_selection,
        _baseline_entries,
        _class_text,
        _evaluate_ratchet,
        _ratchet_result,
        _tail_diagnostics,
    )

    root, check = context.root, context.check
    prefix, prior = context.prefix, context.prior
    spec, start, selected, names = _adapter_selection(context)
    if not selected:
        class_text = _class_text(names)
        reason = (
            f"no files selected (classes: {class_text}); "
            "zero inputs is not a pass"
        )
        print(f"{prefix}: {reason}", file=sys.stderr)
        return _ratchet_result(check, start, "fail", reason=reason)

    evidence_path, settings, failure_diagnostics, message = analysis_step(
        "coverage evidence validation", _crap_required, prior, spec, prefix
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
    if measurement.failures:
        for failure in measurement.failures:
            print(f"{prefix}: {failure}", file=sys.stderr)
        diagnostics = _tail_diagnostics(
            measurement.failures, argv=None, exit_code=1
        )
        return _ratchet_result(
            check,
            start,
            "fail",
            diagnostics=diagnostics,
            reason=diagnostics.output_tail,
        )

    try:
        entries = analysis_step("baseline loading", _baseline_entries, check)
    except GateError as error:
        print(f"{prefix}: {error}", file=sys.stderr)
        return _ratchet_result(
            check,
            start,
            "error",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
            reason=str(error),
        )
    ratchet, failure = _evaluate_ratchet(
        measurement.findings,
        entries,
        check,
        prefix,
        Domain.of_files(selected),
    )
    if ratchet is None:
        return _ratchet_result(check, start, failure or "error", reason=failure)
    outcome = _ratchet_result(
        check,
        start,
        ratchet.outcome,
        ratchet=ratchet,
        measurement={"functions": len(measurement.findings)},
    )
    if ratchet.satisfied:
        noun = "function" if len(measurement.findings) == 1 else "functions"
        print(
            f"{prefix}: {len(measurement.findings)} {noun} within threshold",
            flush=True,
        )
    return outcome
