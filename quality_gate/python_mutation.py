"""Mutation testing for the functions a diff adds or changes.

The adapter selects the production functions a diff touches, generates a fixed
set of statement and expression mutations for each, and runs the test files
that name the function or import its module against a copy of the repository.
A mutant the tests catch is killed; one they do not catch is a finding.

Comparison mutants use the operator's complement and its source spelling.
"""
from __future__ import annotations

import ast
import copy
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from . import module_graph, python_shape
from .files import DiffBase, diff_base
from .json_input import load_json
from .policy import (
    ConfigError,
    GateError,
    _integer,
    _optional_string,
    _string,
)
from .ratchet import Domain, Finding, Location
from .runner import RunResult, execution_outcome, mark_step, run
from .tools import _tools_dir


if TYPE_CHECKING:
    from .adapters import ParsedSpec
    from .checks import CheckResult


METRIC_VERSION = "python-mutation/1"
DEFAULT_MUTANT_SECONDS = 10
DEFAULT_FUNCTION_MUTANTS = 20
DEFAULT_RUN_SECONDS = 300
SCOPES = ("changed",)
_DEFAULT_TEST_PATTERN = "test*.py"


@dataclass(frozen=True)
class MutationSpec:
    scope: str
    base: str
    mutant_seconds: int
    function_mutants: int
    run_seconds: int
    test_runner: str = "unittest"


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
    test_runner = _optional_string(raw, "test_runner", "unittest", path, full_key)
    if test_runner not in ("unittest", "pytest"):
        raise ConfigError(
            f"{path}: {full_key}.test_runner: expected unittest or pytest; got {test_runner!r}"
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
        test_runner,
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
    mutated_source: str = ""


@dataclass(frozen=True)
class _Change:
    operator: str
    target: ast.AST
    replacement: str
    replacement_node: ast.AST | None = None
    delete: bool = False
    rule: str | None = None
    index: int = -1


_FLIPS: dict[type[ast.cmpop], tuple[type[ast.cmpop], str]] = {
    ast.Eq: (ast.NotEq, "!="),
    ast.NotEq: (ast.Eq, "=="),
    ast.Lt: (ast.GtE, ">="),
    ast.LtE: (ast.Gt, ">"),
    ast.Gt: (ast.LtE, "<="),
    ast.GtE: (ast.Lt, "<"),
    ast.In: (ast.NotIn, "not in"),
    ast.NotIn: (ast.In, "in"),
    ast.Is: (ast.IsNot, "is not"),
    ast.IsNot: (ast.Is, "is"),
}


def _self_comparison(left: ast.AST, right: ast.AST) -> bool:
    """Whether both sides are the same plain name or the same constant."""
    if isinstance(left, ast.Name) and isinstance(right, ast.Name):
        return left.id == right.id
    if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
        return ast.dump(left) == ast.dump(right)
    return False


def _comparison_changes(node: ast.Compare) -> list[_Change]:
    changes = []
    for position, operator in enumerate(node.ops):
        flipped = _FLIPS.get(type(operator))
        if flipped is None:
            continue
        flipped_type, text = flipped
        changed = copy.deepcopy(node)
        changed.ops[position] = flipped_type()
        left = node.left if position == 0 else node.comparators[position - 1]
        right = node.comparators[position]
        rule = (
            "self-comparison"
            if _self_comparison(left, right) else None
        )
        changes.append(_Change(
            text, node, ast.unparse(changed), changed, rule=rule,
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
        changed = ast.Return(value=ast.Constant(value=None))
        return [_Change(
            "return None", node, "return None", changed, rule="return None"
        )]
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


def _integer_literal(value: int) -> ast.expr:
    """The expression source for an integer, negative sign included."""
    return ast.parse(str(value), mode="eval").body


def _signed_constant(node: ast.AST) -> int | None:
    """The value of a minus before an integer, or None for another node."""
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and not isinstance(node.operand.value, bool)
        and isinstance(node.operand.value, int)
    ):
        return -node.operand.value
    return None


def _signed_constant_changes(node: ast.UnaryOp) -> list[_Change]:
    """A minus before an integer is one constant, so -1 becomes 0."""
    signed = _signed_constant(node)
    if signed is None:
        return []
    value = signed + 1
    return [
        _Change("n+1", node, str(value), _integer_literal(value))
    ]


def _constant_changes(node: ast.Constant) -> list[_Change]:
    if isinstance(node.value, bool) or node.value is None:
        return []
    if isinstance(node.value, int):
        changed = _integer_literal(node.value + 1)
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
    (ast.UnaryOp, _signed_constant_changes),
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


def _skip_children(node: ast.AST) -> bool:
    """A nested definition's body and a signed literal's digit are not walked."""
    return isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ) or _signed_constant(node) is not None


def _walk(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """The function's own nodes in source order, not a nested definition's."""
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        yield node
        if _skip_children(node):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _raw_changes(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """Every candidate change, ordered by the source position it targets."""
    indexes = {id(node): index for index, node in enumerate(ast.walk(function))}
    changes = [
        replace(change, index=indexes[id(change.target)])
        for node in _walk(function)
        for change in _node_changes(node)
    ]
    return sorted(
        changes,
        key=lambda change: (change.target.lineno, change.target.col_offset),
    )


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


def _statement(
    target: ast.AST, parents: dict[int, tuple[ast.AST, str]]
) -> ast.AST:
    """The statement TARGET is, or the constant expression statement holding it."""
    if isinstance(target, ast.stmt):
        return target
    parent, name = parents.get(id(target), (None, ""))
    if parent is not None and isinstance(parent, ast.Expr) and name == "value":
        return parent
    return target


def _docstring_change(
    function: ast.FunctionDef | ast.AsyncFunctionDef, target: ast.AST,
    parents: dict[int, tuple[ast.AST, str]],
) -> bool:
    """Whether TARGET is the first statement's string, the only docstring."""
    statement = _statement(target, parents)
    return (
        bool(function.body)
        and function.body[0] is statement
        and isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _constant_statement_change(
    target: ast.AST, parents: dict[int, tuple[ast.AST, str]]
) -> bool:
    """Whether TARGET is a bare constant statement, which cannot change behaviour."""
    statement = _statement(target, parents)
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
    )


def _suppression(
    function: ast.FunctionDef | ast.AsyncFunctionDef, change: _Change,
    parents: dict[int, tuple[ast.AST, str]],
) -> str | None:
    if change.rule is not None:
        return change.rule
    if _docstring_change(function, change.target, parents):
        return "docstring"
    if _constant_statement_change(change.target, parents):
        return "constant statement"
    if (
        change.delete
        and _is_function_only_statement(function, change.target, parents)
    ):
        return "only statement"
    return None


def _function_index(
    module: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> int:
    """The walk index of FUNCTION's definition in MODULE."""
    wanted = (
        type(function), function.lineno, function.col_offset, function.name,
    )
    return next(
        index for index, node in enumerate(ast.walk(module))
        if (
            type(node), getattr(node, "lineno", None),
            getattr(node, "col_offset", None), getattr(node, "name", None),
        ) == wanted
    )


def _replace_target(root: ast.AST, index: int, change: _Change) -> None:
    """Apply CHANGE to the node at INDEX in ROOT's walk order."""
    target = list(ast.walk(root))[index]
    parents = _parents(root)
    parent, name = parents[id(target)]
    if change.delete:
        body = _body(parent, name)
        position = body.index(target)
        if len(body) == 1:
            body[position] = ast.copy_location(ast.Pass(), target)
        else:
            del body[position]
        return
    assert change.replacement_node is not None
    replacement = copy.deepcopy(change.replacement_node)
    ast.copy_location(replacement, target)
    value = getattr(parent, name)
    if isinstance(value, list):
        value[value.index(target)] = replacement
    else:
        setattr(parent, name, replacement)


def _ast_mutated(
    module: ast.Module, function_index: int, change: _Change,
) -> ast.Module:
    """A copy of MODULE with CHANGE applied to its target function."""
    mutated = copy.deepcopy(module)
    function = list(ast.walk(mutated))[function_index]
    _replace_target(function, change.index, change)
    return mutated


def _mutated_line(change: _Change, source: str) -> str:
    """The original line with the changed expression, or its deletion marker."""
    target = change.target
    lines = source.split("\n")
    if change.delete:
        statement = lines[target.lineno - 1].encode("utf-8")
        end_column = target.end_col_offset if target.end_lineno == target.lineno else None
        first = statement[target.col_offset:end_column].decode("utf-8")
        return f"deleted: {first}"
    replacement = ast.unparse(change.replacement_node).encode("utf-8")
    start = target.lineno
    end = target.end_lineno or start
    before = lines[start - 1].encode("utf-8")[:target.col_offset]
    after = lines[end - 1].encode("utf-8")[target.end_col_offset:]
    return (before + replacement + after).decode("utf-8").strip()


def _generated_rule(
    mutated_source: str, original: str, path: str,
) -> str | None:
    """The rule that suppresses a mutant, when the mutant source is not one."""
    if mutated_source == original:
        return "unparsed source unchanged"
    try:
        compile(mutated_source, path, "exec")
    except SyntaxError:
        return "does not compile"
    return None


def _mutation(
    function: ast.FunctionDef | ast.AsyncFunctionDef, change: _Change,
    parents: dict[int, tuple[ast.AST, str]], module: ast.Module,
    function_index: int, path: str, original: str, source: str,
) -> Mutation:
    target = change.target
    rule = _suppression(function, change, parents)
    delete_pass = bool(
        change.delete
        and _statement_list(function, target, parents) == [target]
    )
    mutated_source = ast.unparse(
        _ast_mutated(module, function_index, change)
    )
    if rule is None:
        rule = _generated_rule(mutated_source, original, path)
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
        _mutated_line(change, source),
        mutated_source,
    )


def _mutations(
    function: ast.FunctionDef | ast.AsyncFunctionDef, source: str, limit: int,
    path: str = "<mutation>",
) -> list[Mutation]:
    module = ast.parse(source)
    function_index = _function_index(module, function)
    module_function = list(ast.walk(module))[function_index]
    parents = _parents(module_function)
    original = ast.unparse(module)
    found: list[Mutation] = []
    generated = 0
    for change in _raw_changes(module_function):
        mutation = _mutation(
            module_function, change, parents, module, function_index,
            path, original, source,
        )
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
    indexes = {
        relative: python_shape._file_index(
            relative, python_shape._read_source(context.root, relative)
        )
        for relative in paths
    }
    before = python_shape._base_functions(
        context.root, base.commit, sorted(diff.paths.intersection(paths))
    )
    return sorted(
        python_shape._changed_functions(indexes, before),
        key=lambda function: (function.path, function.start_line),
    )


def _selected_test_files(context: Any) -> list[str]:
    from .checks import _select_files

    selected: list[str] = []
    for check in context.config.checks.values():
        if check.adapter == "python_tests":
            files, _names = _select_files(
                context.config, check, context.inventory_files, context.classes
            )
            selected.extend(files)
    return selected


def _discover_directory(run: tuple[str, ...]) -> str:
    for index, argument in enumerate(run[:-1]):
        if argument == "-s":
            return run[index + 1].removeprefix("./").strip("/")
    return ""


def _discover_pattern(run: tuple[str, ...]) -> str:
    for index, argument in enumerate(run[:-1]):
        if argument == "-p":
            return run[index + 1]
    return _DEFAULT_TEST_PATTERN


def _test_discovery(context: Any) -> list[tuple[str, str]]:
    discovery = []
    for check in context.config.checks.values():
        if check.adapter != "python_tests":
            continue
        run = getattr(check.spec, "run", ())
        discovery.append((_discover_directory(run), _discover_pattern(run)))
    return discovery


def _in_test_directory(relative: str, directory: str) -> bool:
    if directory in ("", "."):
        return python_shape._is_test_path(relative)
    return relative == directory or relative.startswith(directory + "/")


def _matches_discovery(relative: str, discovery: list[tuple[str, str]]) -> bool:
    name = PurePosixPath(relative).name
    return any(
        fnmatchcase(name, pattern)
        and (not directory or _in_test_directory(relative, directory))
        for directory, pattern in discovery
    )


def _fallback_test_paths(context: Any) -> list[str]:
    selected = _selected_test_files(context) or context.inventory_files
    return [
        relative for relative in selected
        if python_shape._is_test_path(relative)
    ]


def _matching_test_paths(
    paths: Iterable[str], discovery: list[tuple[str, str]],
) -> list[str]:
    return sorted(
        relative for relative in paths
        if relative.endswith(".py") and _matches_discovery(relative, discovery)
    )


def _pytest_test_file_paths(context: Any) -> list[str]:
    return _matching_test_paths(
        _fallback_test_paths(context), [("", "test_*.py"), ("", "*_test.py")],
    )


def _test_file_paths(context: Any) -> list[str]:
    discovery = _test_discovery(context)
    directory_rules = [
        (directory, pattern) for directory, pattern in discovery if directory
    ]
    if directory_rules:
        return _matching_test_paths(context.inventory_files, directory_rules)
    return _matching_test_paths(
        _fallback_test_paths(context), discovery or [("", _DEFAULT_TEST_PATTERN)],
    )


def _imported_from(node: ast.ImportFrom) -> set[str]:
    """The module names one 'from' import makes available."""
    base = node.module or ""
    modules = {base} if base else set()
    modules.update(
        f"{base}.{alias.name}" if base else alias.name
        for alias in node.names if alias.name != "*"
    )
    return modules


def _imported_modules(
    node: ast.Import | ast.ImportFrom, modules: set[str],
) -> None:
    """Add the module names one import statement makes available."""
    if isinstance(node, ast.Import):
        modules.update(alias.name for alias in node.names)
        return
    modules.update(_imported_from(node))


def _test_references(
    relative: str, source: str,
) -> tuple[set[str], set[str]]:
    """The names a test file mentions and the modules it imports."""
    tree = python_shape._parse_tree(relative, source)
    names: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            _imported_modules(node, modules)
    return names, modules


def _tests_by_function(
    root: Path, functions: list[python_shape.ShapeFunction],
    test_files: list[str], module_names: dict[str, frozenset[str]],
) -> dict[str, tuple[str, ...]]:
    references = {
        relative: _test_references(
            relative, python_shape._read_source(root, relative)
        )
        for relative in test_files
    }
    return {
        function.identity: tuple(
            relative for relative, (names, modules) in references.items()
            if function.final_name in names
            or not module_names[function.path].isdisjoint(modules)
        )
        for function in functions
    }


def _copy_directory(copy_root: Path, name: str) -> Path:
    path = copy_root / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def _inherited_path(source_root: Path, copy_root: Path) -> str:
    """PATH, absolute, with each entry inside SOURCE_ROOT moved into COPY_ROOT."""
    source = Path(os.path.realpath(source_root))
    copy = Path(os.path.realpath(copy_root))
    entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        resolved = Path(os.path.realpath(entry))
        if resolved.is_relative_to(source):
            entries.append(str(copy / resolved.relative_to(source)))
        else:
            entries.append(str(resolved))
    return os.pathsep.join(entries)


def _environment(
    source_root: Path, copy_root: Path, tools_dir: Path
) -> dict[str, str]:
    """The allowlisted environment for a test running inside the copy."""
    from .python_tests import _test_environment

    exported = _test_environment([sys.executable, "-I", "-B"])
    environment = {
        name: os.environ[name]
        for name in ("LANG", "LC_ALL")
        if name in os.environ
    }
    if "PATH" in os.environ:
        environment["PATH"] = _inherited_path(source_root, copy_root)
    environment.update({
        name: exported[name]
        for name in ("QG_PYTHON", "PYTHONDONTWRITEBYTECODE")
    })
    environment["PWD"] = str(copy_root)
    environment["HOME"] = str(_copy_directory(copy_root, "home"))
    environment["TMPDIR"] = str(_copy_directory(copy_root, "tmp"))
    environment["QG_TOOLS_DIR"] = str(tools_dir)
    return environment


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


def _run_one_test(
    source_root: Path, copy_root: Path, relative: str, deadline: float,
    tools_dir: Path,
) -> RunResult:
    argv = _discover_argv(relative)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _budget_result(argv)
    return run(
        argv, cwd=copy_root, env=_environment(source_root, copy_root, tools_dir),
        budget_seconds=remaining,
    )


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
    source_root: Path, copy_root: Path, tests: tuple[str, ...], seconds: float,
    tools_dir: Path,
) -> RunResult:
    assert tests
    deadline = time.monotonic() + seconds
    failure: RunResult | None = None
    for relative in tests:
        result = _run_one_test(source_root, copy_root, relative, deadline, tools_dir)
        if not execution_outcome(result.execution).completed:
            return result
        failure = _first_failure(failure, result)
    return _result_or_failure(result, failure)


@dataclass(frozen=True)
class _PytestEvidence:
    collected: tuple[str, ...]
    executed: tuple[str, ...]
    assertions: tuple[str, ...]


def _pytest_names(receipt: dict[str, Any], key: str) -> tuple[str, ...]:
    values = receipt.get(key)
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"invalid {key} in pytest evidence")
    if len(set(values)) != len(values):
        raise ValueError(f"duplicate {key} in pytest evidence")
    return tuple(sorted(values))


def _read_pytest_evidence(report: Path, returncode: int | None) -> _PytestEvidence:
    receipt = load_json(report.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("invalid pytest evidence")
    errors = _pytest_names(receipt, "errors")
    if errors:
        raise ValueError("; ".join(errors[:3]))
    evidence = _PytestEvidence(
        _pytest_names(receipt, "collected"),
        _pytest_names(receipt, "executed"),
        _pytest_names(receipt, "assertions"),
    )
    if not evidence.executed:
        raise ValueError("pytest executed zero selected tests")
    if not set(evidence.assertions) <= set(evidence.executed) <= set(evidence.collected):
        raise ValueError("inconsistent collection and execution in pytest evidence")
    if returncode != int(bool(evidence.assertions)):
        raise ValueError(f"pytest exited {returncode} without a verified test outcome")
    return evidence


def _run_pytest(
    source_root: Path, copy_root: Path, tests: tuple[str, ...], seconds: float,
    tools_dir: Path, target: str, *, stage: str, total_budget_cut: bool,
) -> _PytestEvidence | None:
    script = Path(__file__).resolve().with_name("pytest_mutation_run.py")
    report = copy_root.with_suffix(".pytest.json")
    result = run(
        [
            sys.executable, "-I", "-B", str(script), str(source_root),
            str(report), target, *tests,
        ],
        cwd=copy_root, env=_environment(source_root, copy_root, tools_dir),
        budget_seconds=seconds,
    )
    subject = f"python-mutation: pytest {stage} for {target}"
    return _pytest_result(result, report, subject, seconds, total_budget_cut)


def _pytest_result(
    result: RunResult, report: Path, subject: str, seconds: float, total_budget_cut: bool,
) -> _PytestEvidence | None:
    execution = execution_outcome(result.execution)
    if execution.budget:
        if total_budget_cut:
            return None
        raise GateError(f"{subject} timed out after {seconds:g} s")
    if not execution.completed:
        raise GateError(f"{subject} could not complete: {result.error or result.execution}")
    return _verify_pytest_report(result, report, subject)


def _verify_pytest_report(result: RunResult, report: Path, subject: str) -> _PytestEvidence:
    try:
        return _read_pytest_evidence(report, result.returncode)
    except (OSError, ValueError) as error:
        detail = result.stderr_text.strip() or result.stdout_text.strip()
        raise GateError(f"{subject} could not be verified: {error}\n{detail[-2000:]}") from error


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


def _baseline_passed(
    function: python_shape.ShapeFunction, result: RunResult,
    allowance: float, mutant_seconds: int,
) -> bool:
    """Whether the baseline passed, was cut by the budget, or was an error."""
    if _passed(result):
        return True
    execution = execution_outcome(result.execution)
    if execution.error:
        raise GateError(
            f"python-mutation: the original tests for {function.identity} "
            f"could not run in the allowlisted mutation environment: "
            f"{result.error}"
        )
    if execution.budget and allowance < mutant_seconds:
        return False
    detail = result.stderr_text.strip() or result.stdout_text.strip()
    raise GateError(
        f"python-mutation: the original tests do not pass for "
        f"{function.identity} in the allowlisted mutation environment "
        f"within {allowance:g} s: {detail[-2000:]}"
    )


def _baseline(
    function: python_shape.ShapeFunction, tests: tuple[str, ...],
    root: Path, work: Path, number: int, spec: MutationSpec, start: float,
    tools_dir: Path,
) -> bool | _PytestEvidence:
    remaining = _remaining(start, spec)
    if remaining <= 0:
        return False
    copy_root = _fresh_copy(root, work, number)
    remaining = _remaining(start, spec)
    if remaining <= 0:
        return False
    allowance = min(spec.mutant_seconds, remaining)
    if spec.test_runner == "pytest":
        return _pytest_baseline(function, tests, root, copy_root, allowance, spec, start, tools_dir)
    result = _run_unittest(root, copy_root, tests, allowance, tools_dir)
    if not _baseline_passed(
        function, result, allowance, spec.mutant_seconds
    ):
        return False
    return _remaining(start, spec) > 0


def _pytest_baseline(
    function: python_shape.ShapeFunction, tests: tuple[str, ...], root: Path, copy_root: Path,
    allowance: float, spec: MutationSpec, start: float, tools_dir: Path,
) -> bool | _PytestEvidence:
    evidence = _run_pytest(
        root, copy_root, tests, allowance, tools_dir, function.path,
        stage="original tests", total_budget_cut=allowance < spec.mutant_seconds,
    )
    if evidence is None:
        return False
    if evidence.assertions:
        raise GateError(
            f"python-mutation: pytest original tests for {function.identity} failed: "
            + ", ".join(evidence.assertions[:3])
        )
    return evidence if _remaining(start, spec) > 0 else False


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


def _not_run_records(
    function: python_shape.ShapeFunction, mutations: list[Mutation],
    tests: tuple[str, ...],
) -> list[dict[str, Any]]:
    return [
        _record(function, mutation, tests, "not run (over budget)")
        for mutation in mutations
    ]


def _run_mutant(
    function: python_shape.ShapeFunction, mutation: Mutation,
    tests: tuple[str, ...], spec: MutationSpec,
    start: float, root: Path, work: Path, numbers: list[int], tools_dir: Path,
    baseline: bool | _PytestEvidence = True,
) -> tuple[str, bool]:
    if _remaining(start, spec) <= 0:
        return "not run (over budget)", True
    copy_root = _fresh_copy(root, work, numbers[0])
    numbers[0] += 1
    (copy_root / function.path).write_text(
        mutation.mutated_source, encoding="utf-8"
    )
    remaining = _remaining(start, spec)
    if remaining <= 0:
        return "not run (over budget)", True
    allowance = min(spec.mutant_seconds, remaining)
    if spec.test_runner == "pytest":
        evidence = _run_pytest(
            root, copy_root, tests, allowance, tools_dir, function.path,
            stage="mutant run", total_budget_cut=allowance < spec.mutant_seconds,
        )
        outcome = _pytest_outcome(function, baseline, evidence)
    else:
        result = _run_unittest(root, copy_root, tests, allowance, tools_dir)
        outcome = _outcome(result, function)
    over_budget = (
        outcome == "timed out" and allowance < spec.mutant_seconds
    )
    return outcome, over_budget or _remaining(start, spec) <= 0


def _pytest_outcome(
    function: python_shape.ShapeFunction, baseline: bool | _PytestEvidence,
    evidence: _PytestEvidence | None,
) -> str:
    assert isinstance(baseline, _PytestEvidence)
    if evidence is None:
        return "timed out"
    if (evidence.collected, evidence.executed) != (baseline.collected, baseline.executed):
        raise GateError(
            f"python-mutation: pytest mutant run for {function.identity} "
            "collected or executed different tests from the original"
        )
    return "killed" if evidence.assertions else "survived"


def _run_generated(
    function: python_shape.ShapeFunction, mutations: list[Mutation],
    tests: tuple[str, ...], spec: MutationSpec,
    start: float, root: Path, work: Path, numbers: list[int],
    records: list[dict[str, Any]], tools_dir: Path,
    baseline: bool | _PytestEvidence = True,
) -> tuple[list[dict[str, Any]], list[Finding], bool]:
    findings: list[Finding] = []
    for position, mutation in enumerate(mutations):
        if _remaining(start, spec) <= 0:
            records.extend(
                _not_run_records(function, mutations[position:], tests)
            )
            return records, findings, False
        outcome, over_budget = _run_mutant(
            function, mutation, tests, spec, start,
            root, work, numbers, tools_dir, baseline,
        )
        records.append(_record(function, mutation, tests, outcome))
        if over_budget:
            records.extend(
                _not_run_records(function, mutations[position + 1:], tests)
            )
            return records, findings, False
        if outcome == "survived":
            findings.append(_survived_finding(function, mutation, tests))
    return records, findings, True


def _run_function(
    function: python_shape.ShapeFunction, tests: tuple[str, ...],
    source: str, spec: MutationSpec, start: float,
    root: Path, work: Path, numbers: list[int], tools_dir: Path,
) -> tuple[list[dict[str, Any]], list[Finding], bool]:
    if _remaining(start, spec) <= 0:
        return [], [], False
    mutations = _mutations(
        function.node, source, spec.function_mutants, function.path
    )
    records = _suppressed_records(function, mutations, tests)
    generated = _generated_mutations(mutations)
    if _remaining(start, spec) <= 0:
        return records + _not_run_records(function, generated, tests), [], False
    baseline = _baseline(function, tests, root, work, numbers[0], spec, start, tools_dir)
    if not baseline:
        return records + _not_run_records(function, generated, tests), [], False
    numbers[0] += 1
    if not generated:
        return records, [], True
    return _run_generated(
        function, generated, tests, spec, start,
        root, work, numbers, records, tools_dir, baseline,
    )


def _source_for(
    root: Path, relative: str, sources: dict[str, str]
) -> str:
    source = sources.get(relative)
    if source is None:
        source = python_shape._read_source(root, relative)
        sources[relative] = source
    return source


def _unfinished_after_cleanup(
    functions: list[python_shape.ShapeFunction],
    unfinished: list[python_shape.ShapeFunction],
    start: float, spec: MutationSpec,
) -> list[python_shape.ShapeFunction]:
    """The unfinished functions, adding the last when the final cleanup overran."""
    if unfinished:
        return unfinished
    if not functions:
        return unfinished
    if _remaining(start, spec) > 0:
        return unfinished
    return [*unfinished, functions[-1]]


def _measure(
    context: Any, spec: MutationSpec, functions: list[python_shape.ShapeFunction],
    tests: dict[str, tuple[str, ...]], start: float,
) -> tuple[list[dict[str, Any]], list[Finding], list[python_shape.ShapeFunction]]:
    records: list[dict[str, Any]] = []
    findings: list[Finding] = []
    unfinished: list[python_shape.ShapeFunction] = []
    sources: dict[str, str] = {}
    tools_dir = _tools_dir().resolve()
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
                context.root, work, numbers, tools_dir,
            )
            records.extend(related)
            findings.extend(survived)
            if not finished:
                unfinished.extend(functions[index:])
                break
    return records, findings, _unfinished_after_cleanup(
        functions, unfinished, start, spec
    )


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
        test_files = (
            _pytest_test_file_paths(context) if check.spec.test_runner == "pytest"
            else _test_file_paths(context)
        )
        imports = module_graph.PythonImports.from_repository(context.root, context.config.python_import_roots)
        tests = _tests_by_function(
            context.root, functions, test_files, imports.identities(context.inventory_files),
        )
        mark_step("python-mutation execution")
        records, findings, unfinished = _measure(
            context, check.spec, functions, tests, start
        )
        findings.extend(
            _over_budget_finding(function, check.spec)
            for function in unfinished
        )
    except (GateError, OSError, ValueError) as error:
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
