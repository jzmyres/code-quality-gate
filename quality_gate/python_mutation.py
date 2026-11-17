"""Mutation testing for the functions a diff adds or changes.

The adapter selects the production functions a diff touches, generates a fixed
set of statement and expression mutations for each, and runs the test files
that name the function or import its module against a copy of the repository.
A mutant the tests catch is killed; one they do not catch is a finding.
"""
from __future__ import annotations

import ast
import copy
import os
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from . import python_shape
from .files import DiffBase, diff_base
from .policy import (
    ConfigError,
    GateError,
    _integer,
    _optional_string,
    _string,
)
from .ratchet import Domain, Finding, Location
from .runner import RunResult, execution_outcome, mark_step, run


if TYPE_CHECKING:
    from .adapters import ParsedSpec
    from .checks import CheckResult


METRIC_VERSION = "python-mutation/1"
DEFAULT_MUTANT_SECONDS = 10
DEFAULT_FUNCTION_MUTANTS = 20
DEFAULT_RUN_SECONDS = 300
SCOPES = ("changed",)


@dataclass(frozen=True)
class MutationSpec:
    scope: str
    base: str
    mutant_seconds: int
    function_mutants: int
    run_seconds: int


def _budget(spec: MutationSpec) -> int:
    return spec.run_seconds


def _python_mutation_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    """Parse the changed-scope base and the three mutation budgets."""
    from .adapters import ParsedSpec

    scope = _optional_string(raw, "scope", "changed", path, full_key)
    if scope not in SCOPES:
        raise ConfigError(
            f"{path}: {full_key}.scope: expected changed; got {scope!r}"
        )
    spec = MutationSpec(
        scope,
        _string(raw, "base", path, f"{full_key}.base"),
        _integer(
            raw, "mutant_seconds", path, f"{full_key}.mutant_seconds",
            default=DEFAULT_MUTANT_SECONDS, minimum=1,
        ),
        _integer(
            raw, "function_mutants", path, f"{full_key}.function_mutants",
            default=DEFAULT_FUNCTION_MUTANTS, minimum=1,
        ),
        _integer(
            raw, "run_seconds", path, f"{full_key}.run_seconds",
            default=DEFAULT_RUN_SECONDS, minimum=1,
        ),
    )
    return ParsedSpec(spec, METRIC_VERSION, ("static",), threshold=0)


@dataclass(frozen=True)
class Mutation:
    """One generated or suppressed change to a function."""

    operator: str
    line: int
    column: int
    end_line: int
    end_column: int
    replacement: str
    index: int
    replacement_node: ast.AST | None = None
    delete: bool = False
    delete_pass: bool = False
    rule: str | None = None
    mutated_line: str = ""


@dataclass(frozen=True)
class _Change:
    operator: str
    target: ast.AST
    replacement: str
    replacement_node: ast.AST | None = None
    delete: bool = False
    rule: str | None = None
    index: int = -1


_FLIPS = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}

_OPERATOR_TEXT = {
    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
    ast.Gt: ">", ast.GtE: ">=", ast.In: "in", ast.NotIn: "not in",
    ast.Is: "is", ast.IsNot: "is not",
}


def _comparison_changes(node: ast.Compare) -> list[_Change]:
    changes = []
    for position, operator in enumerate(node.ops):
        flipped = _FLIPS.get(type(operator))
        if flipped is None:
            continue
        changed = copy.deepcopy(node)
        changed.ops[position] = flipped()
        left = node.left if position == 0 else node.comparators[position - 1]
        right = node.comparators[position]
        rule = (
            "self-comparison" if ast.dump(left) == ast.dump(right) else None
        )
        changes.append(_Change(
            _OPERATOR_TEXT[flipped], node, ast.unparse(changed), changed,
            rule=rule,
        ))
    return changes


def _boolean_changes(node: ast.BoolOp) -> list[_Change]:
    flipped = ast.Or if isinstance(node.op, ast.And) else ast.And
    changed = copy.deepcopy(node)
    changed.op = flipped()
    name = "or" if flipped is ast.Or else "and"
    return [_Change(name, node, ast.unparse(changed), changed)]


def _negation(target: ast.AST) -> _Change:
    changed = ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(target))
    return _Change("not", target, f"not ({ast.unparse(target)})", changed)


def _condition_changes(node: ast.If | ast.While | ast.IfExp) -> list[_Change]:
    return [_negation(node.test)]


def _comprehension_changes(node: ast.comprehension) -> list[_Change]:
    return [_negation(test) for test in node.ifs]


def _return_changes(node: ast.Return) -> list[_Change]:
    value = node.value
    if value is None:
        return [_Change("return None", node, "", rule="return None")]
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        changed = ast.Constant(value=not value.value)
        return [_Change(
            f"return {not value.value}", value, ast.unparse(changed), changed
        )]
    changed = ast.Constant(value=None)
    rule = "return None" if (
        isinstance(value, ast.Constant) and value.value is None
    ) else None
    return [_Change("return None", value, "None", changed, rule=rule)]


def _constant_changes(node: ast.Constant) -> list[_Change]:
    if isinstance(node.value, bool) or node.value is None:
        return []
    if isinstance(node.value, int):
        changed = ast.Constant(value=node.value + 1)
        return [_Change("n+1", node, str(node.value + 1), changed)]
    if isinstance(node.value, str):
        changed = ast.Constant(value="")
        return [_Change("empty string", node, "''", changed)]
    return []


_CHANGE_BUILDERS = (
    (ast.Compare, _comparison_changes),
    (ast.BoolOp, _boolean_changes),
    (ast.If, _condition_changes),
    (ast.While, _condition_changes),
    (ast.IfExp, _condition_changes),
    (ast.comprehension, _comprehension_changes),
    (ast.Return, _return_changes),
    (ast.Constant, _constant_changes),
)


def _node_changes(node: ast.AST) -> list[_Change]:
    changes = (
        [_Change("delete", node, "", delete=True)]
        if isinstance(node, ast.stmt) else []
    )
    for wanted, build in _CHANGE_BUILDERS:
        if isinstance(node, wanted):
            changes.extend(build(node))
    return changes


def _walk(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """The function's own nodes in source order, not a nested definition's."""
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _raw_changes(function: ast.FunctionDef | ast.AsyncFunctionDef):
    indexes = {id(node): index for index, node in enumerate(ast.walk(function))}
    for node in _walk(function):
        for change in _node_changes(node):
            yield replace(change, index=indexes[id(change.target)])


def _child_nodes(value: Any) -> list[ast.AST]:
    if isinstance(value, list):
        return [child for child in value if isinstance(child, ast.AST)]
    return [value] if isinstance(value, ast.AST) else []


def _parents(root: ast.AST) -> dict[int, tuple[ast.AST, str]]:
    found: dict[int, tuple[ast.AST, str]] = {}
    for parent in ast.walk(root):
        for name, value in ast.iter_fields(parent):
            for child in _child_nodes(value):
                found[id(child)] = (parent, name)
    return found


def _body(parent: ast.AST, name: str) -> list[ast.AST]:
    value = getattr(parent, name)
    assert isinstance(value, list)
    return value


def _statement_list(
    function: ast.FunctionDef | ast.AsyncFunctionDef, target: ast.AST,
    parents: dict[int, tuple[ast.AST, str]],
) -> list[ast.AST] | None:
    parent, name = parents.get(id(target), (None, ""))
    if parent is None or not isinstance(getattr(parent, name, None), list):
        return None
    return _body(parent, name)


def _is_function_only_statement(
    function: ast.FunctionDef | ast.AsyncFunctionDef, target: ast.AST,
    parents: dict[int, tuple[ast.AST, str]],
) -> bool:
    parent, name = parents.get(id(target), (None, ""))
    if parent is not function or name != "body":
        return False
    statements = [
        item for item in function.body
        if not python_shape._is_docstring(item)
    ]
    return statements == [target]


def _docstring_change(
    target: ast.AST, parents: dict[int, tuple[ast.AST, str]]
) -> bool:
    if python_shape._is_docstring(target):
        return True
    parent, _name = parents.get(id(target), (None, ""))
    return parent is not None and python_shape._is_docstring(parent)


def _suppression(
    function: ast.FunctionDef | ast.AsyncFunctionDef, change: _Change,
    parents: dict[int, tuple[ast.AST, str]],
) -> str | None:
    if change.rule is not None:
        return change.rule
    if _docstring_change(change.target, parents):
        return "docstring"
    if (
        change.delete
        and _is_function_only_statement(function, change.target, parents)
    ):
        return "only statement"
    return None


def _ast_mutated(
    function: ast.FunctionDef | ast.AsyncFunctionDef, change: _Change,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    mutated = copy.deepcopy(function)
    target = list(ast.walk(mutated))[change.index]
    parents = _parents(mutated)
    parent, name = parents[id(target)]
    if change.delete:
        body = _body(parent, name)
        position = body.index(target)
        if len(body) == 1:
            body[position] = ast.copy_location(ast.Pass(), target)
        else:
            del body[position]
        return mutated
    assert change.replacement_node is not None
    replacement = copy.deepcopy(change.replacement_node)
    ast.copy_location(replacement, target)
    value = getattr(parent, name)
    if isinstance(value, list):
        value[value.index(target)] = replacement
    else:
        setattr(parent, name, replacement)
    return mutated


def _offset(source: str, line: int, column: int) -> int:
    lines = source.splitlines(keepends=True)
    before = sum(len(item) for item in lines[: line - 1])
    prefix = lines[line - 1].encode("utf-8")[:column].decode("utf-8")
    return before + len(prefix)


def _apply_text(source: str, change: _Change, delete_pass: bool) -> str:
    target = change.target
    start = _offset(source, target.lineno, target.col_offset)
    end = _offset(source, target.end_lineno, target.end_col_offset)
    replacement = change.replacement
    if change.delete:
        replacement = "pass" if delete_pass else ""
    return source[:start] + replacement + source[end:]


def _apply_mutation(source: str, mutation: Mutation) -> str:
    start = _offset(source, mutation.line, mutation.column)
    end = _offset(source, mutation.end_line, mutation.end_column)
    replacement = mutation.replacement
    if mutation.delete:
        replacement = "pass" if mutation.delete_pass else ""
    return source[:start] + replacement + source[end:]


def _mutated_line(
    source: str, change: _Change, delete_pass: bool, line: int
) -> str:
    if change.rule == "return None":
        return "return None"
    changed = _apply_text(source, change, delete_pass)
    lines = changed.splitlines()
    text = lines[line - 1].strip() if line <= len(lines) else ""
    if text:
        return text
    return "pass" if delete_pass else "(statement deleted)"


def _mutation(
    function: ast.FunctionDef | ast.AsyncFunctionDef, change: _Change,
    parents: dict[int, tuple[ast.AST, str]], source: str, original: str,
) -> Mutation:
    target = change.target
    rule = _suppression(function, change, parents)
    delete_pass = bool(
        change.delete
        and _statement_list(function, target, parents) == [target]
    )
    if rule is None:
        mutated = _ast_mutated(function, change)
        if ast.unparse(mutated) == original:
            rule = "unparsed source unchanged"
    return Mutation(
        change.operator,
        target.lineno,
        target.col_offset,
        target.end_lineno or target.lineno,
        target.end_col_offset or target.col_offset,
        change.replacement,
        change.index,
        change.replacement_node,
        change.delete,
        delete_pass,
        rule,
        _mutated_line(source, change, delete_pass, target.lineno),
    )


def _mutations(
    function: ast.FunctionDef | ast.AsyncFunctionDef, source: str, limit: int,
) -> list[Mutation]:
    parents = _parents(function)
    original = ast.unparse(function)
    found: list[Mutation] = []
    generated = 0
    for change in _raw_changes(function):
        mutation = _mutation(function, change, parents, source, original)
        found.append(mutation)
        if mutation.rule is None:
            generated += 1
            if generated >= limit:
                break
    return found


def _changed_functions(
    context: Any, spec: MutationSpec, base: DiffBase,
) -> list[python_shape.ShapeFunction]:
    diff = python_shape._diff_lines(context.root, base.commit)
    paths = python_shape._measured_paths(context, spec, diff)
    found: list[python_shape.ShapeFunction] = []
    for relative in paths:
        tree = python_shape._parse_tree(
            relative, python_shape._read_source(context.root, relative)
        )
        definitions: list[python_shape.ShapeFunction] = []
        python_shape._collect_definitions(tree.body, "", relative, definitions)
        found.extend(
            function for function in definitions
            if python_shape._touched(spec, diff, function)
        )
    return sorted(found, key=lambda function: (function.path, function.start_line))


def _selected_test_files(context: Any) -> list[str]:
    from .checks import _select_files

    selected: list[str] = []
    for check in context.config.checks.values():
        if check.adapter == "python_tests":
            files, _names = _select_files(
                context.config, check, context.files, context.classes
            )
            selected.extend(files)
    return selected


def _discover_directory(run: tuple[str, ...]) -> str:
    for index, argument in enumerate(run[:-1]):
        if argument == "-s":
            return run[index + 1].removeprefix("./").strip("/")
    return ""


def _test_directories(context: Any) -> list[str]:
    directories = []
    for check in context.config.checks.values():
        if check.adapter != "python_tests":
            continue
        directory = _discover_directory(getattr(check.spec, "run", ()))
        if directory:
            directories.append(directory)
    return directories


def _in_test_directory(relative: str, directory: str) -> bool:
    if directory in ("", "."):
        return python_shape._is_test_path(relative)
    return relative == directory or relative.startswith(directory + "/")


def _in_any_directory(relative: str, directories: list[str]) -> bool:
    return any(
        _in_test_directory(relative, directory)
        for directory in directories
    )


def _fallback_test_paths(context: Any) -> list[str]:
    selected = _selected_test_files(context) or list(context.files)
    return [
        relative for relative in selected
        if python_shape._is_test_path(relative)
    ]


def _selected_test_paths(
    context: Any, directories: list[str]
) -> list[str]:
    if not directories:
        return _fallback_test_paths(context)
    return [
        relative for relative in context.files
        if _in_any_directory(relative, directories)
    ]


def _test_file_paths(context: Any) -> list[str]:
    selected = _selected_test_paths(context, _test_directories(context))
    return sorted(
        relative for relative in selected if relative.endswith(".py")
    )


def _module_name(relative: str) -> str:
    return relative.removesuffix(".py").replace("/", ".")


def _mentioned(source: str, name: str) -> bool:
    return re.search(
        rf"(?<!\w){re.escape(name)}(?!\w)", source
    ) is not None


def _mentions(source: str, function: python_shape.ShapeFunction) -> bool:
    return (
        _mentioned(source, function.final_name)
        or _mentioned(source, _module_name(function.path))
    )


def _tests_by_function(
    root: Path, functions: list[python_shape.ShapeFunction],
    test_files: list[str],
) -> dict[str, tuple[str, ...]]:
    contents = {
        relative: python_shape._read_source(root, relative)
        for relative in test_files
    }
    return {
        function.identity: tuple(
            relative for relative, source in contents.items()
            if _mentions(source, function)
        )
        for function in functions
    }


def _environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("COVERAGE_") and key != "PYTHONPATH"
    }


def _discover_argv(relative: str) -> list[str]:
    path = PurePosixPath(relative)
    start = path.parent.as_posix() or "."
    return [
        sys.executable, "-I", "-B", "-m", "unittest", "discover",
        "-s", start, "-p", path.name,
    ]


def _budget_result(argv: list[str]) -> RunResult:
    return RunResult(
        argv=tuple(argv), execution="budget", returncode=None, timed_out=True
    )


def _run_one_test(root: Path, relative: str, deadline: float) -> RunResult:
    argv = _discover_argv(relative)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _budget_result(argv)
    return run(argv, cwd=root, env=_environment(), budget_seconds=remaining)


def _first_failure(
    failure: RunResult | None, result: RunResult
) -> RunResult | None:
    if failure is not None:
        return failure
    return result if result.returncode != 0 else None


def _result_or_failure(
    result: RunResult, failure: RunResult | None
) -> RunResult:
    return failure if failure is not None else result


def _run_unittest(
    root: Path, tests: tuple[str, ...], seconds: float
) -> RunResult:
    deadline = time.monotonic() + seconds
    result: RunResult | None = None
    failure: RunResult | None = None
    for relative in tests:
        result = _run_one_test(root, relative, deadline)
        if not execution_outcome(result.execution).completed:
            return result
        failure = _first_failure(failure, result)
    assert result is not None
    return _result_or_failure(result, failure)


def _fresh_copy(source: Path, work: Path, number: int) -> Path:
    destination = work / f"copy-{number:04d}"
    shutil.copytree(
        source, destination,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", ".ruff_cache", ".pytest_cache"
        ),
    )
    return destination


def _passed(result: Any) -> bool:
    return (
        execution_outcome(result.execution).completed
        and result.returncode == 0
    )


def _baseline(
    function: python_shape.ShapeFunction, tests: tuple[str, ...],
    root: Path, work: Path, number: int, allowance: float,
    mutant_seconds: int,
) -> bool:
    copy_root = _fresh_copy(root, work, number)
    result = _run_unittest(copy_root, tests, allowance)
    if _passed(result):
        return True
    if (
        execution_outcome(result.execution).budget
        and allowance < mutant_seconds
    ):
        return False
    detail = result.stderr_text.strip() or result.stdout_text.strip()
    raise GateError(
        f"python-mutation: the original tests do not pass for "
        f"{function.identity} within {allowance:g} s: {detail[-500:]}"
    )


def _outcome(result: Any, function: python_shape.ShapeFunction) -> str:
    execution = execution_outcome(result.execution)
    if execution.budget:
        return "timed out"
    if execution.error:
        raise GateError(
            f"python-mutation: the mutant run for {function.identity} failed: "
            f"{result.error}"
        )
    return "survived" if result.returncode == 0 else "killed"


def _record(
    function: python_shape.ShapeFunction, mutation: Mutation,
    tests: tuple[str, ...], outcome: str,
) -> dict[str, Any]:
    return {
        "subject": function.identity,
        "file": function.path,
        "function": function.name,
        "operator": mutation.operator,
        "line": mutation.line,
        "mutated": mutation.mutated_line,
        "outcome": outcome,
        "rule": mutation.rule,
        "tests": list(tests),
    }


def _survived_finding(
    function: python_shape.ShapeFunction, mutation: Mutation,
    tests: tuple[str, ...],
) -> Finding:
    subject = (
        f"python-mutation: {function.path}:{mutation.line} {function.name} "
        f"survives {mutation.operator} ({mutation.mutated_line}); tests run: "
        f"{', '.join(tests)}. Add a test that fails on this change, or fix the "
        "generation rule if the mutant cannot change behaviour."
    )
    measurement = _record(function, mutation, tests, "survived")
    measurement["rule"] = "SURVIVED"
    return Finding(
        subject, 1, function.identity, measurement,
        (Location(function.path, function.start_line, function.end_line),),
    )


def _no_test_finding(function: python_shape.ShapeFunction) -> Finding:
    subject = (
        f"python-mutation: {function.path}:{function.start_line} "
        f"{function.name}: no test names it; tests run: none. Add a test that "
        "names the function or imports its module."
    )
    measurement = {
        "rule": "NO-TEST", "file": function.path, "function": function.name,
        "line": function.start_line, "outcome": "not generated",
        "tests": [],
    }
    return Finding(
        subject, 1, function.identity, measurement,
        (Location(function.path, function.start_line, function.end_line),),
    )


def _over_budget_finding(
    function: python_shape.ShapeFunction, spec: MutationSpec,
) -> Finding:
    subject = (
        f"python-mutation: {function.path}:{function.start_line} "
        f"{function.name} over budget (run_seconds {spec.run_seconds:g}); the "
        "check stopped before its mutants finished"
    )
    measurement = {
        "rule": "OVER-BUDGET", "file": function.path, "function": function.name,
        "line": function.start_line, "outcome": "not finished",
        "tests": [],
    }
    return Finding(
        subject, 1, function.identity, measurement,
        (Location(function.path, function.start_line, function.end_line),),
    )


def _remaining(start: float, spec: MutationSpec) -> float:
    return spec.run_seconds - (time.monotonic() - start)


def _suppressed_records(
    function: python_shape.ShapeFunction, mutations: list[Mutation],
    tests: tuple[str, ...],
) -> list[dict[str, Any]]:
    return [
        _record(function, mutation, tests, "not generated")
        for mutation in mutations if mutation.rule is not None
    ]


def _generated_mutations(mutations: list[Mutation]) -> list[Mutation]:
    return [mutation for mutation in mutations if mutation.rule is None]


def _run_mutant(
    function: python_shape.ShapeFunction, mutation: Mutation,
    tests: tuple[str, ...], source: str, spec: MutationSpec,
    start: float, root: Path, work: Path, numbers: list[int],
) -> tuple[str, bool]:
    copy_root = _fresh_copy(root, work, numbers[0])
    numbers[0] += 1
    (copy_root / function.path).write_text(
        _apply_mutation(source, mutation), encoding="utf-8"
    )
    remaining = _remaining(start, spec)
    if remaining <= 0:
        return "timed out", True
    allowance = min(spec.mutant_seconds, remaining)
    result = _run_unittest(copy_root, tests, allowance)
    outcome = _outcome(result, function)
    return outcome, (
        outcome == "timed out" and allowance < spec.mutant_seconds
    )


def _run_generated(
    function: python_shape.ShapeFunction, mutations: list[Mutation],
    tests: tuple[str, ...], source: str, spec: MutationSpec,
    start: float, root: Path, work: Path, numbers: list[int],
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[Finding], bool]:
    findings: list[Finding] = []
    for mutation in mutations:
        if _remaining(start, spec) <= 0:
            return records, findings, False
        outcome, over_budget = _run_mutant(
            function, mutation, tests, source, spec, start,
            root, work, numbers,
        )
        records.append(_record(function, mutation, tests, outcome))
        if over_budget:
            return records, findings, False
        if outcome == "survived":
            findings.append(_survived_finding(function, mutation, tests))
    return records, findings, True


def _run_function(
    function: python_shape.ShapeFunction, tests: tuple[str, ...],
    source: str, spec: MutationSpec, start: float,
    root: Path, work: Path, numbers: list[int],
) -> tuple[list[dict[str, Any]], list[Finding], bool]:
    if _remaining(start, spec) <= 0:
        return [], [], False
    mutations = _mutations(function.node, source, spec.function_mutants)
    records = _suppressed_records(function, mutations, tests)
    generated = _generated_mutations(mutations)
    if not generated:
        return records, [], True
    baseline_allowance = min(
        spec.mutant_seconds, _remaining(start, spec)
    )
    if not _baseline(
        function, tests, root, work, numbers[0], baseline_allowance,
        spec.mutant_seconds,
    ):
        return records, [], False
    numbers[0] += 1
    return _run_generated(
        function, generated, tests, source, spec, start,
        root, work, numbers, records,
    )


def _source_for(
    root: Path, relative: str, sources: dict[str, str]
) -> str:
    source = sources.get(relative)
    if source is None:
        source = python_shape._read_source(root, relative)
        sources[relative] = source
    return source


def _measure(
    context: Any, spec: MutationSpec, functions: list[python_shape.ShapeFunction],
    tests: dict[str, tuple[str, ...]], start: float,
) -> tuple[list[dict[str, Any]], list[Finding], list[python_shape.ShapeFunction]]:
    records: list[dict[str, Any]] = []
    findings: list[Finding] = []
    unfinished: list[python_shape.ShapeFunction] = []
    sources: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="qg-mutation-") as temporary:
        work = Path(temporary)
        numbers = [0]
        for index, function in enumerate(functions):
            if _remaining(start, spec) <= 0:
                unfinished.extend(functions[index:])
                break
            function_tests = tests[function.identity]
            if not function_tests:
                findings.append(_no_test_finding(function))
                continue
            source = _source_for(context.root, function.path, sources)
            related, survived, finished = _run_function(
                function, function_tests, source, spec, start,
                context.root, work, numbers,
            )
            records.extend(related)
            findings.extend(survived)
            if not finished:
                unfinished.extend(functions[index:])
                break
    return records, findings, unfinished


def _mutation_result(
    context: Any, check: Any, start: float,
    functions: list[python_shape.ShapeFunction],
    records: list[dict[str, Any]], test_files: list[str], base: DiffBase,
    measured: Domain, findings: list[Finding],
) -> CheckResult:
    from .checks import _evaluate_ratchet, _ratchet_result

    ratchet, failure = _evaluate_ratchet(
        findings, [], check, context.prefix, measured
    )
    if ratchet is None:
        result = _ratchet_result(check, start, failure, reason=failure)
    else:
        if ratchet.satisfied:
            print(
                f"{context.prefix}: {len(functions)} functions measured, "
                f"{len(records)} mutants",
                flush=True,
            )
        result = _ratchet_result(
            check, start, ratchet.outcome, ratchet=ratchet,
            measurement={
                "functions": len(functions),
                "mutants": records,
                "test_files": test_files,
                "base": base.measurement(),
            },
        )
    result.budget_seconds = check.spec.run_seconds
    return result


def _run_python_mutation(context: Any) -> CheckResult:
    from .checks import _ratchet_error

    check = context.check
    start = time.monotonic()
    try:
        base = diff_base(
            context.root, check.spec.base, resolved=context.base_override
        )
        mark_step("python-mutation selection")
        functions = _changed_functions(context, check.spec, base)
        test_files = _test_file_paths(context)
        tests = _tests_by_function(context.root, functions, test_files)
        mark_step("python-mutation execution")
        records, findings, unfinished = _measure(
            context, check.spec, functions, tests, start
        )
        findings.extend(
            _over_budget_finding(function, check.spec)
            for function in unfinished
        )
    except (GateError, OSError) as error:
        result = _ratchet_error(check, start, context.prefix, error)
        result.configuration_error = True
        result.budget_seconds = check.spec.run_seconds
        return result
    mark_step("python-mutation rules")
    measured = Domain.of_files(
        sorted({function.path for function in functions}),
        "the measured production files",
    )
    return _mutation_result(
        context, check, start, functions, records, test_files, base, measured,
        findings,
    )
