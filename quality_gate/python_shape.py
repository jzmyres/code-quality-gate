"""Function-shape checks: CRAP-payoff fragmentation, pass-through wrappers,
single-caller chains and shattered duplicates.

One parse of the selected production files feeds four structural rules.  A
finding is a violation of the rule's predicate, reported as value 1 against
threshold 0, so any finding fails the check: there is no baseline key and no
suppression.  A missing or invalid input is a configuration error, never a
skipped rule.
"""
from __future__ import annotations

import ast
import io
import keyword
import time
import tokenize
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from .files import _git, _split_nul, _untracked_files, git_argv
from .policy import (
    ConfigError,
    GateError,
    _integer,
    _number,
    _optional_string,
    _string,
)
from .python_crap import (
    _function_identity,
    _is_docstring,
    _start_line,
    cyclomatic_complexity,
)
from .ratchet import Domain, Finding, Location
from .runner import mark_step, run


if TYPE_CHECKING:
    from .adapters import ParsedSpec


METRIC_VERSION = "python-shape/1"
SCOPES = ("changed", "tree")
DEFAULT_MAX_CHAIN = 6
DEFAULT_CLONE_MIN_TOKENS = 30
DEFAULT_CLONE_SIMILARITY = 0.95
# One below the clone detector's 50-token minimum: this rule covers the gap.
CLONE_MAX_TOKENS = 49
_SKIPPED_TOKENS = frozenset({
    tokenize.ENCODING, tokenize.NEWLINE, tokenize.NL, tokenize.INDENT,
    tokenize.DEDENT, tokenize.COMMENT, tokenize.ENDMARKER,
})
# A string literal is one token; the literal pieces of an f-string are data,
# so only its interpolated expressions stay tokens.  The start stands for the
# whole literal prefix and the end closes it without adding structure.
_STRING_TOKENS = frozenset({tokenize.STRING, tokenize.FSTRING_START})
_DATA_TOKENS = frozenset({tokenize.FSTRING_MIDDLE, tokenize.FSTRING_END})


@dataclass(frozen=True)
class ShapeSpec:
    scope: str
    base: str
    max_chain: int
    clone_min_tokens: int
    clone_similarity: float
    crap_check: str


def _shape_scope(
    raw: dict[str, Any], path: Path, full_key: str
) -> str:
    scope = _optional_string(raw, "scope", "changed", path, full_key)
    if scope not in SCOPES:
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of changed, tree; "
            f"got {scope!r}"
        )
    return scope


def _similarity(
    raw: dict[str, Any], path: Path, full_key: str
) -> float:
    value = _number(
        raw,
        "clone_similarity",
        path,
        f"{full_key}.clone_similarity",
        default=DEFAULT_CLONE_SIMILARITY,
        minimum=0.5,
    )
    if value > 1.0:
        raise ConfigError(
            f"{path}: {full_key}.clone_similarity: expected a finite number "
            f"in [0.5, 1.0], got {value:g}"
        )
    return value


def _python_shape_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    spec = ShapeSpec(
        _shape_scope(raw, path, full_key),
        _string(raw, "base", path, f"{full_key}.base"),
        _integer(
            raw, "max_chain", path, f"{full_key}.max_chain",
            default=DEFAULT_MAX_CHAIN, minimum=1,
        ),
        _integer(
            raw, "clone_min_tokens", path, f"{full_key}.clone_min_tokens",
            default=DEFAULT_CLONE_MIN_TOKENS, minimum=20,
            maximum=CLONE_MAX_TOKENS,
        ),
        _similarity(raw, path, full_key),
        _string(raw, "crap_check", path, f"{full_key}.crap_check"),
    )
    return ParsedSpec(spec, METRIC_VERSION, ("duplication",), threshold=0)


@dataclass(frozen=True)
class ShapeFunction:
    identity: str
    path: str
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    start_line: int
    end_line: int
    cc: int
    final_name: str


@dataclass(frozen=True)
class CallSite:
    name: str
    target: str
    path: str
    line: int
    caller: str | None


@dataclass(frozen=True)
class Diff:
    """What the diff adds: its paths, its added lines and its new files."""

    paths: frozenset[str]
    added: dict[str, frozenset[int]]
    whole: frozenset[str]


@dataclass(frozen=True)
class FileIndex:
    functions: tuple[ShapeFunction, ...]
    calls: tuple[CallSite, ...]
    tests: frozenset[str]


@dataclass(frozen=True)
class Wrapper:
    callee: str
    forwarded: tuple[str, ...]
    constants: int


@dataclass(frozen=True)
class ShapeInput:
    functions: tuple[ShapeFunction, ...]
    before: dict[str, dict[str, int]]
    added: tuple[ShapeFunction, ...]
    candidates: tuple[ShapeFunction, ...]
    calls: dict[str, tuple[CallSite, ...]]
    tests: frozenset[str]
    spec: ShapeSpec
    limit: float


def _is_test_path(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if "tests" in parts:
        return True
    name = parts[-1] if parts else relative
    return name.startswith("test_") or name.endswith("_test.py")


def _definition(
    node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str, path: str
) -> ShapeFunction:
    name = _function_identity(node, prefix)
    return ShapeFunction(
        identity=f"{path}:{name}",
        path=path,
        name=name,
        node=node,
        start_line=_start_line(node),
        end_line=node.end_lineno or node.lineno,
        cc=cyclomatic_complexity(
            ast.Module(body=node.body, type_ignores=[])
        ),
        final_name=node.name,
    )


def _collect_definitions(
    nodes: list[ast.AST], prefix: str, path: str,
    found: list[ShapeFunction],
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = _definition(node, prefix, path)
            found.append(function)
            _collect_definitions(node.body, f"{function.name}.", path, found)
            continue
        if isinstance(node, ast.ClassDef):
            _collect_definitions(node.body, f"{prefix}{node.name}.", path, found)
            continue
        _collect_definitions(list(ast.iter_child_nodes(node)), prefix, path, found)


def _dotted(node: ast.AST) -> str | None:
    """The dotted spelling of a called name, so a wrapper names its callee."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _final_name(target: str) -> str:
    return target.rpartition(".")[2]


def _walk_calls(
    node: ast.AST, enclosing: str | None, relative: str,
    identities: dict[int, str], found: list[CallSite],
) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _walk_calls(child, identities[id(child)], relative, identities, found)
            continue
        if isinstance(child, ast.Call):
            target = _dotted(child.func)
            if target is not None:
                found.append(CallSite(
                    _final_name(target), target, relative, child.lineno,
                    enclosing,
                ))
        _walk_calls(child, enclosing, relative, identities, found)


def _is_test_class(name: str) -> bool:
    return name.startswith("Test") or name.endswith(("Test", "Tests"))


def _add_references(node: ast.AST, found: set[str]) -> None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)


def _test_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef, in_test: bool,
    found: set[str],
) -> None:
    if in_test or node.name.startswith("test"):
        _add_references(node, found)
        return
    _test_functions(node.body, False, found)


def _test_functions(
    nodes: list[ast.AST], in_test: bool, found: set[str]
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _test_function(node, in_test, found)
        elif isinstance(node, ast.ClassDef):
            _test_functions(
                node.body, in_test or _is_test_class(node.name), found
            )
        else:
            _test_functions(list(ast.iter_child_nodes(node)), in_test, found)


def _parse_tree(relative: str, source: str) -> ast.Module:
    try:
        return ast.parse(source, filename=relative)
    except SyntaxError as error:
        raise GateError(f"cannot parse {relative}: {error}") from error


def _file_index(relative: str, source: str) -> FileIndex:
    tree = _parse_tree(relative, source)
    functions: list[ShapeFunction] = []
    _collect_definitions(tree.body, "", relative, functions)
    identities = {id(item.node): item.identity for item in functions}
    calls: list[CallSite] = []
    _walk_calls(tree, None, relative, identities, calls)
    tests: set[str] = set()
    if _is_test_path(relative):
        _test_functions(tree.body, False, tests)
    return FileIndex(tuple(functions), tuple(calls), frozenset(tests))


def _read_source(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise GateError(f"cannot read {relative}: {error}") from error


def _index_files(root: Path, paths: list[str]) -> dict[str, FileIndex]:
    return {
        path: _file_index(path, _read_source(root, path)) for path in paths
    }


def _check_base(root: Path, base: str) -> None:
    result = run(
        git_argv(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"),
        budget_seconds=600,
        capture_limit=None,
    )
    if result.execution != "completed":
        raise GateError(
            f"base {base!r}: expected an existing revision, "
            f"got git {result.execution}"
        )
    if result.returncode != 0:
        raise GateError(
            f"base {base!r}: expected an existing revision, got no such revision"
        )


def _start_path(paths: set[str], added: dict[str, set[int]], line: str) -> str | None:
    """A diff header line starts the next file's added-line set."""
    path = _new_path(line[4:])
    if path is None:
        return None
    paths.add(path)
    added.setdefault(path, set())
    return path


def _hunks(
    lines: list[str]
) -> tuple[set[str], dict[str, set[int]]]:
    """The after paths of a zero-context diff and each one's added lines."""
    paths: set[str] = set()
    added: dict[str, set[int]] = {}
    path: str | None = None
    for line in lines:
        if line.startswith("+++ "):
            path = _start_path(paths, added, line)
        elif path is not None and line.startswith("@@"):
            added[path].update(_hunk_lines(line))
    return paths, added


def _diff_lines(root: Path, base: str) -> Diff:
    """The added line numbers of every changed path, and new whole files."""
    _check_base(root, base)
    raw = _git(
        root,
        [
            "-c", "core.quotePath=false",
            "diff", "--unified=0", "--no-color", "--no-ext-diff",
            "--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=ACMRTUXB",
            base, "--",
        ],
        "python-shape diff",
    )
    paths, added = _hunks(raw.decode("utf-8", "surrogateescape").splitlines())
    untracked = frozenset(
        _untracked_files(root, "python-shape untracked-file selection")
    )
    return Diff(
        frozenset(paths) | untracked,
        {name: frozenset(lines) for name, lines in added.items()},
        untracked,
    )


def _base_paths(root: Path, base: str) -> set[str]:
    raw = _git(
        root,
        ["ls-tree", "-r", "-z", "--name-only", base, "--"],
        "python-shape base tree",
    )
    return set(_split_nul(raw))


def _new_path(raw: str) -> str | None:
    """The after path of a diff header line, or None for a deletion."""
    if raw == "/dev/null":
        return None
    if raw.startswith('"'):
        raise GateError(
            f"python-shape diff: quoted path {raw}; expected an unquoted path"
        )
    return raw.removeprefix("b/")


def _hunk_lines(header: str) -> range:
    """The added line numbers of one zero-context hunk header."""
    after = header.split("+", 1)[1].split(" ", 1)[0]
    start_text, _comma, count_text = after.partition(",")
    start = int(start_text)
    count = int(count_text) if count_text else 1
    return range(start, start + count)


def _decode(relative: str, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"cannot decode {relative}: {error}") from error


def _before_complexity(
    relative: str, source: str
) -> dict[str, int]:
    """Each function's cyclomatic complexity in the before tree."""
    tree = _parse_tree(relative, source)
    functions: list[ShapeFunction] = []
    _collect_definitions(tree.body, "", relative, functions)
    return {function.identity: function.cc for function in functions}


def _before_complexities(
    root: Path, base: str, paths: list[str]
) -> dict[str, dict[str, int]]:
    """The before tree's per-function complexity, for CPF's comparison."""
    existing = _base_paths(root, base)
    before: dict[str, dict[str, int]] = {}
    for relative in paths:
        if relative not in existing:
            before[relative] = {}
            continue
        data = _git(
            root,
            ["show", f"{base}:{relative}"],
            "python-shape base content",
        )
        before[relative] = _before_complexity(
            relative, _decode(relative, data)
        )
    return before


def _selected_production(context: Any) -> list[str]:
    from .checks import _select_files

    selected, _class_names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    return [
        relative for relative in selected if not _is_test_path(relative)
    ]


def _definition_lines(function: ShapeFunction) -> set[int]:
    return {function.start_line, function.node.lineno}


def _touched_by(
    added: frozenset[int] | None, function: ShapeFunction
) -> bool:
    """A whole-file addition touches every line; otherwise the added ones."""
    if added is None:
        return True
    return any(
        function.start_line <= line <= function.end_line for line in added
    )


def _inserted(diff: Diff, function: ShapeFunction) -> bool:
    """The diff adds the function's definition line."""
    if function.path in diff.whole:
        return True
    added = diff.added.get(function.path, frozenset())
    return bool(_definition_lines(function) & added)


def _changed_or_added(diff: Diff, function: ShapeFunction) -> bool:
    if function.path in diff.whole:
        return True
    return _touched_by(diff.added.get(function.path), function)


def _mentions(source: str, names: set[str]) -> bool:
    return any(name in source for name in names)


def _scan_candidate(relative: str, known: set[str]) -> bool:
    return relative.endswith(".py") and relative not in known


def _scan_files(
    context: Any, scoped: list[str], names: set[str]
) -> dict[str, FileIndex]:
    """The files outside the measured scope that mention an added name."""
    indexes: dict[str, FileIndex] = {}
    if not names:
        return indexes
    known = set(scoped)
    for relative in context.files:
        if not _scan_candidate(relative, known):
            continue
        source = _read_source(context.root, relative)
        if _mentions(source, names):
            indexes[relative] = _file_index(relative, source)
    return indexes


def _call_index(
    indexes: list[FileIndex], names: set[str]
) -> dict[str, tuple[CallSite, ...]]:
    calls: dict[str, list[CallSite]] = {}
    for index in indexes:
        for site in index.calls:
            if site.name in names:
                calls.setdefault(site.name, []).append(site)
    return {name: tuple(sites) for name, sites in calls.items()}


def _test_index(indexes: list[FileIndex]) -> frozenset[str]:
    found: set[str] = set()
    for index in indexes:
        found.update(index.tests)
    return frozenset(found)


def _evaluated(
    spec: ShapeSpec, diff: Diff, function: ShapeFunction
) -> bool:
    """A tree run evaluates every function; a changed run its added or changed."""
    if spec.scope == "tree":
        return True
    return _changed_or_added(diff, function)


def _candidates(
    spec: ShapeSpec, functions: tuple[ShapeFunction, ...],
    added: tuple[ShapeFunction, ...],
) -> tuple[ShapeFunction, ...]:
    """The functions PTW-SU, SCC and LTC judge: a tree's, or the added ones."""
    return functions if spec.scope == "tree" else added


def _selected_functions(
    indexes: dict[str, FileIndex], select: Callable[[ShapeFunction], bool],
) -> tuple[ShapeFunction, ...]:
    return tuple(
        function
        for index in indexes.values() for function in index.functions
        if select(function)
    )


def _measured_paths(
    context: Any, spec: ShapeSpec, diff: Diff
) -> list[str]:
    """A tree run measures every selected file; a changed run the changed ones."""
    selected = _selected_production(context)
    if spec.scope == "tree":
        return selected
    return [path for path in selected if path in diff.paths]


def _shape_input(
    context: Any, spec: ShapeSpec, limit: float
) -> ShapeInput:
    """One parse of the measured files, and the indexes every rule reads."""
    diff = _diff_lines(context.root, spec.base)
    scoped = _measured_paths(context, spec, diff)
    indexes = _index_files(context.root, scoped)
    functions = _selected_functions(
        indexes, lambda function: _evaluated(spec, diff, function)
    )
    added = _selected_functions(
        indexes, lambda function: _inserted(diff, function)
    )
    candidates = _candidates(spec, functions, added)
    names = {function.final_name for function in candidates}
    scanned = _scan_files(context, scoped, names)
    parsed = [*indexes.values(), *scanned.values()]
    # CPF is the one rule that compares against the before tree, and only for
    # the files the diff touches; every other rule reads the after tree alone.
    before = _before_complexities(
        context.root, spec.base,
        [path for path in scoped if path in diff.paths],
    )
    return ShapeInput(
        functions, before, added, candidates, _call_index(parsed, names),
        _test_index(parsed), spec, limit,
    )


def _crap_limit(config: Any, spec: ShapeSpec) -> float:
    check = config.checks.get(spec.crap_check)
    if check is None:
        known = ", ".join(config.checks) or "none"
        raise GateError(
            f"crap_check {spec.crap_check!r}: expected the id of a python_crap "
            f"check, got an unknown check; known checks: {known}"
        )
    if check.adapter != "python_crap" or check.threshold is None:
        raise GateError(
            f"crap_check {spec.crap_check!r}: expected the id of a python_crap "
            f"check, got a {check.adapter} check"
        )
    return check.threshold


def _inside(site: CallSite, function: ShapeFunction) -> bool:
    """A call on the function's own lines, nested bodies included, is not a use."""
    return (
        site.path == function.path
        and function.start_line <= site.line <= function.end_line
    )


def _single_call_site(
    data: ShapeInput, function: ShapeFunction
) -> CallSite | None:
    """The function's one call site outside its own body, if it has exactly one."""
    sites = [
        site for site in data.calls.get(function.final_name, ())
        if not _inside(site, function)
    ]
    return sites[0] if len(sites) == 1 else None


def _has_direct_test(data: ShapeInput, function: ShapeFunction) -> bool:
    return function.final_name in data.tests


def _parameter_names(arguments: ast.arguments) -> tuple[str, ...]:
    """A method's implicit receiver is not one of its parameters."""
    names = [
        argument.arg
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]
        if argument is not None
    ]
    first = names[0] if names else None
    return tuple(names[1:] if first in ("self", "cls") else names)


def _call_of(value: ast.AST) -> ast.Call | None:
    if isinstance(value, ast.Await):
        value = value.value
    return value if isinstance(value, ast.Call) else None


def _body_call(statement: ast.stmt) -> ast.Call | None:
    if isinstance(statement, ast.Expr):
        return _call_of(statement.value)
    if isinstance(statement, ast.Return) and statement.value is not None:
        return _call_of(statement.value)
    return None


def _without_docstring(statements: list[ast.stmt]) -> list[ast.stmt]:
    if statements and _is_docstring(statements[0]):
        return statements[1:]
    return statements


def _forwarded_name(value: ast.AST, own: tuple[str, ...]) -> str | None:
    if isinstance(value, ast.Name):
        return value.id if value.id in own else None
    return "" if isinstance(value, ast.Constant) else None


def _forwards(names: list[str], own: tuple[str, ...]) -> list[str] | None:
    """The called names, when every own parameter is forwarded exactly once."""
    if not names or sorted(names) != sorted(own):
        return None
    return names


def _argument_values(call: ast.Call) -> list[ast.AST] | None:
    if any(keyword.arg is None for keyword in call.keywords):
        return None
    return [*call.args, *(keyword.value for keyword in call.keywords)]


def _usable_call(
    call: ast.Call, own: tuple[str, ...]
) -> tuple[str, list[ast.AST]] | None:
    """The callee and argument values, when the callee is not a parameter."""
    callee = _dotted(call.func)
    if callee is None or callee in own:
        return None
    values = _argument_values(call)
    return None if values is None else (callee, values)


def _forwarded_values(
    values: list[ast.AST], own: tuple[str, ...]
) -> list[str] | None:
    forwarded = [_forwarded_name(value, own) for value in values]
    if None in forwarded:
        return None
    return _forwards([name for name in forwarded if name], own)


def _wrapper_call(
    call: ast.Call, arguments: ast.arguments
) -> Wrapper | None:
    own = _parameter_names(arguments)
    usable = _usable_call(call, own)
    if usable is None:
        return None
    callee, values = usable
    forwarded = _forwarded_values(values, own)
    if forwarded is None:
        return None
    constants = sum(isinstance(value, ast.Constant) for value in values)
    return Wrapper(callee, tuple(forwarded), constants)


def _wrapper(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Wrapper | None:
    statements = _without_docstring(node.body)
    if len(statements) != 1:
        return None
    call = _body_call(statements[0])
    return None if call is None else _wrapper_call(call, node.args)


def _span(function: ShapeFunction) -> str:
    return f"{function.path}:{function.start_line}-{function.end_line}"


def _location(function: ShapeFunction) -> Location:
    return Location(function.path, function.start_line, function.end_line)


def _number_text(value: float) -> str:
    return f"{value:g}"


def _crap_payoff(before: int, after: int, limit: float) -> bool:
    """The complexity fell from above the CRAP limit to at most it."""
    return before > limit >= after


def _cpf_targets(
    data: ShapeInput
) -> dict[str, tuple[int, ShapeFunction]]:
    """The functions the diff lowered from above the CRAP limit to at most it."""
    targets: dict[str, tuple[int, ShapeFunction]] = {}
    for function in data.functions:
        before = data.before.get(function.path, {}).get(function.identity)
        if before is not None and _crap_payoff(before, function.cc, data.limit):
            targets[function.identity] = (before, function)
    return targets


def _gratuitous(data: ShapeInput, function: ShapeFunction) -> bool:
    """A single-use helper with no direct test: the fragmenting shape."""
    return (
        _single_call_site(data, function) is not None
        and not _has_direct_test(data, function)
    )


def _gratuitous_helpers(data: ShapeInput) -> list[ShapeFunction]:
    return [
        function for function in data.added if _gratuitous(data, function)
    ]


def _cpf_findings(data: ShapeInput) -> list[Finding]:
    targets = _cpf_targets(data)
    findings = []
    for helper in _gratuitous_helpers(data):
        site = _single_call_site(data, helper)
        target = targets.get(site.caller) if site is not None else None
        if target is not None:
            findings.append(_cpf_finding(data, target[0], target[1], helper))
    return findings


def _cpf_finding(
    data: ShapeInput, before: int, target: ShapeFunction,
    helper: ShapeFunction,
) -> Finding:
    subject = (
        f"CPF {target.identity} CC {before} -> {target.cc}, helper "
        f"{helper.identity} (1 call site, no direct test; limit "
        f"{_number_text(data.limit)} CC; expected the helper to have a direct "
        "test or a second caller, or the function to stay unsplit)"
    )
    measurement = {
        "rule": "CPF",
        "file": target.path,
        "name": target.name,
        "caller": target.identity,
        "helper": helper.identity,
        "helper_file": helper.path,
        "helper_name": helper.name,
        "call_sites": 1,
        "direct_test": False,
        "cc_before": before,
        "cc_after": target.cc,
        "limit": data.limit,
    }
    return Finding(
        subject, 1, _span(target), measurement,
        (_location(target), _location(helper)),
    )


def _ptw_wrapper(
    data: ShapeInput, function: ShapeFunction
) -> Wrapper | None:
    """The wrapper a pass-through, single-use, untested added function is."""
    if not _gratuitous(data, function):
        return None
    return _wrapper(function.node)


def _ptw_findings(data: ShapeInput) -> list[Finding]:
    findings = []
    for function in data.candidates:
        wrapper = _ptw_wrapper(data, function)
        if wrapper is not None:
            findings.append(_ptw_finding(function, wrapper))
    return findings


def _ptw_finding(function: ShapeFunction, wrapper: Wrapper) -> Finding:
    subject = (
        f"PTW-SU {function.identity} -> {wrapper.callee} (forwards "
        f"{', '.join(wrapper.forwarded)}, {wrapper.constants} constants, "
        "1 call site, no direct test; limit 1 call site with no direct test; "
        "expected a direct test, a second caller, or no wrapper)"
    )
    measurement = {
        "rule": "PTW-SU",
        "file": function.path,
        "name": function.name,
        "callee": wrapper.callee,
        "forwarded": list(wrapper.forwarded),
        "constants": wrapper.constants,
        "call_sites": 1,
        "direct_test": False,
    }
    return Finding(
        subject, 1, _span(function), measurement, (_location(function),)
    )


def _chain_successors(
    data: ShapeInput, candidates: dict[str, ShapeFunction]
) -> dict[str, list[str]]:
    successors: dict[str, list[str]] = {}
    for function in data.candidates:
        site = _single_call_site(data, function)
        if site is None or site.caller not in candidates:
            continue
        successors.setdefault(site.caller, []).append(function.identity)
    return successors


def _chain_heads(
    data: ShapeInput, successors: dict[str, list[str]]
) -> list[str]:
    targets = {
        target for values in successors.values() for target in values
    }
    return [
        function.identity for function in data.candidates
        if function.identity not in targets
    ]


def _chain_path(
    identity: str, successors: dict[str, list[str]], visiting: frozenset[str]
) -> tuple[int, list[str]]:
    if identity in visiting:
        return 1, [identity]
    visited = visiting | {identity}
    best = (1, [identity])
    for target in successors.get(identity, ()):
        depth, path = _chain_path(target, successors, visited)
        if depth + 1 > best[0]:
            best = (depth + 1, [identity, *path])
    return best


def _chain_too_long(depth: int, limit: int) -> bool:
    """A chain deeper than the policy allows."""
    return depth > limit


def _long_chains(
    data: ShapeInput, successors: dict[str, list[str]]
) -> list[list[str]]:
    return [
        chain
        for head in _chain_heads(data, successors)
        for depth, chain in [_chain_path(head, successors, frozenset())]
        if _chain_too_long(depth, data.spec.max_chain)
    ]


def _scc_findings(data: ShapeInput) -> list[Finding]:
    candidates = ({function.identity: function for function in data.candidates})
    successors = _chain_successors(data, candidates)
    return [
        _scc_finding(data, candidates, chain)
        for chain in _long_chains(data, successors)
    ]


def _scc_finding(
    data: ShapeInput, added: dict[str, ShapeFunction], chain: list[str]
) -> Finding:
    limit = data.spec.max_chain
    subject = (
        f"SCC chain depth {len(chain)}: {' -> '.join(chain)} (limit {limit}; "
        f"expected at most {limit} consecutive single-caller functions)"
    )
    measurement = {
        "rule": "SCC",
        "chain_depth": len(chain),
        "chain": list(chain),
        "limit": limit,
    }
    members = [added[identity] for identity in chain]
    return Finding(
        subject, 1, _span(members[0]), measurement,
        tuple(_location(member) for member in members),
    )


def _token_text(token: tokenize.TokenInfo) -> str:
    if token.type == tokenize.NAME:
        return token.string if keyword.iskeyword(token.string) else "ID"
    if token.type == tokenize.NUMBER:
        return "N"
    if token.type in _STRING_TOKENS:
        return "S"
    return token.string


def _normalised_tokens(
    node: ast.FunctionDef | ast.AsyncFunctionDef
) -> tuple[str, ...]:
    """The body's tokens with identifiers, numbers and strings normalised."""
    body = _without_docstring(node.body)
    text = ast.unparse(ast.Module(body=body, type_ignores=[]))
    return tuple(
        _token_text(token)
        for token in tokenize.generate_tokens(io.StringIO(text).readline)
        if token.type not in _SKIPPED_TOKENS
        and token.type not in _DATA_TOKENS
    )


def _windows(sequence: tuple[str, ...], minimum: int) -> set[tuple[str, ...]]:
    return {
        sequence[index:index + minimum]
        for index in range(len(sequence) - minimum + 1)
    }


def _window_buckets(
    functions: tuple[ShapeFunction, ...],
    tokens: dict[str, tuple[str, ...]], minimum: int,
) -> dict[tuple[str, ...], list[str]]:
    buckets: dict[tuple[str, ...], list[str]] = {}
    for function in functions:
        for window in _windows(tokens[function.identity], minimum):
            buckets.setdefault(window, []).append(function.identity)
    return buckets


def _pairs_of(identities: list[str]) -> set[tuple[str, str]]:
    return {
        (first, second)
        for index, first in enumerate(identities)
        for second in identities[index + 1:]
    }


def _clone_pairs(
    functions: tuple[ShapeFunction, ...],
    tokens: dict[str, tuple[str, ...]], minimum: int,
) -> list[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for identities in _window_buckets(functions, tokens, minimum).values():
        pairs.update(_pairs_of(identities))
    return sorted(pairs)


def _longest_common_run(
    first: tuple[str, ...], second: tuple[str, ...]
) -> int:
    previous = [0] * (len(second) + 1)
    best = 0
    for left in first:
        current = [0] * (len(second) + 1)
        for index, right in enumerate(second, 1):
            if left == right:
                current[index] = previous[index - 1] + 1
                best = max(best, current[index])
        previous = current
    return best


def _ancestor(first: ShapeFunction, second: ShapeFunction) -> bool:
    return (
        second.name.startswith(first.name + ".")
        or first.name.startswith(second.name + ".")
    )


def _ltc_pair(
    data: ShapeInput, left: ShapeFunction, right: ShapeFunction,
    tokens: dict[str, tuple[str, ...]],
) -> Finding | None:
    if _ancestor(left, right):
        return None
    return _clone_finding(data, left, right, tokens)


def _ltc_findings(data: ShapeInput) -> list[Finding]:
    tokens = {
        function.identity: _normalised_tokens(function.node)
        for function in data.candidates
    }
    by_identity = {
        function.identity: function for function in data.candidates
    }
    findings = []
    for first, second in _clone_pairs(
        data.candidates, tokens, data.spec.clone_min_tokens
    ):
        finding = _ltc_pair(
            data, by_identity[first], by_identity[second], tokens
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _shattered(
    spec: ShapeSpec, shorter: int, run: int, ratio: float
) -> bool:
    """A run in the gap below the clone detector's minimum, at high similarity."""
    return (
        shorter > 0
        and spec.clone_min_tokens <= run <= CLONE_MAX_TOKENS
        and ratio >= spec.clone_similarity
    )


def _clone_finding(
    data: ShapeInput, first: ShapeFunction, second: ShapeFunction,
    tokens: dict[str, tuple[str, ...]],
) -> Finding | None:
    first_tokens = tokens[first.identity]
    second_tokens = tokens[second.identity]
    shorter = min(len(first_tokens), len(second_tokens))
    run = _longest_common_run(first_tokens, second_tokens)
    ratio = run / shorter if shorter else 0.0
    if not _shattered(data.spec, shorter, run, ratio):
        return None
    subject = (
        f"LTC {first.identity} <-> {second.identity} ({run} normalised "
        f"tokens, similarity {ratio:.2f}; limit {data.spec.clone_min_tokens}"
        f"-{CLONE_MAX_TOKENS} tokens at similarity "
        f"{_number_text(data.spec.clone_similarity)}; expected no duplicated "
        "run below the clone detector's 50-token minimum)"
    )
    measurement = {
        "rule": "LTC",
        "first": first.identity,
        "second": second.identity,
        "longest": run,
        "ratio": ratio,
        "tokens": [len(first_tokens), len(second_tokens)],
        "limit": {
            "min_tokens": data.spec.clone_min_tokens,
            "max_tokens": CLONE_MAX_TOKENS,
            "similarity": data.spec.clone_similarity,
        },
    }
    return Finding(
        subject, 1, _span(first), measurement,
        (_location(first), _location(second)),
    )


RULES: tuple[Callable[[ShapeInput], list[Finding]], ...] = (
    _cpf_findings, _ptw_findings, _scc_findings, _ltc_findings,
)


def _findings(data: ShapeInput) -> list[Finding]:
    """One finding per violation of any rule, in subject order."""
    findings = [
        finding
        for rule in RULES
        for finding in rule(data)
    ]
    findings.sort(key=lambda item: item.subject)
    return findings


def _configuration_error(
    check: Any, start: float, prefix: str, error: Exception
) -> Any:
    from .checks import _ratchet_error

    result = _ratchet_error(check, start, prefix, error)
    result.configuration_error = True
    return result


def _shape_domain(data: ShapeInput) -> Domain:
    return Domain.of_files(
        sorted({function.path for function in data.functions}),
        "the measured production files",
    )


def _run_python_shape(context: Any) -> Any:
    from .checks import _evaluate_ratchet, _ratchet_result

    check = context.check
    start = time.monotonic()
    try:
        limit = _crap_limit(context.config, check.spec)
        mark_step("python-shape analysis")
        data = _shape_input(context, check.spec, limit)
    except GateError as error:
        return _configuration_error(check, start, context.prefix, error)
    mark_step("python-shape rules")
    ratchet, failure = _evaluate_ratchet(
        _findings(data), [], check, context.prefix, _shape_domain(data)
    )
    if ratchet is None:
        return _ratchet_result(check, start, failure or "error", reason=failure)
    result = _ratchet_result(
        check, start, ratchet.outcome, ratchet=ratchet,
        measurement={
            "functions": len(data.functions),
            "added": len(data.added),
        },
    )
    if ratchet.satisfied:
        print(
            f"{context.prefix}: {len(data.functions)} functions measured",
            flush=True,
        )
    return result
