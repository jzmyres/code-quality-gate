"""Function-shape checks: uncalled functions, CRAP-payoff fragmentation,
pass-through wrappers, single-caller chains and shattered duplicates.

One parse of the selected production files feeds five structural rules.  A
finding is a violation of the rule's predicate, reported as value 1 against
threshold 0, so any finding fails the check: there is no baseline key and no
suppression.  A missing or invalid input is a configuration error, never a
skipped rule.

The duplicate-fragment rule tops out at 49 tokens, just below the
clone detector's 50-token minimum.
"""
from __future__ import annotations

import ast
import io
import itertools
import keyword
import time
import tokenize
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from .files import DiffBase, _git, _split_nul, _untracked_files, diff_base, is_python_program
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
from .runner import mark_step


if TYPE_CHECKING:
    from .adapters import ParsedSpec


METRIC_VERSION = "python-shape/1"
SCOPES = ("changed", "tree")
DEFAULT_MAX_CHAIN = 6
DEFAULT_CLONE_MIN_TOKENS = 30
DEFAULT_CLONE_SIMILARITY = 0.95
CLONE_MAX_TOKENS = 49
_SKIPPED_TOKENS = frozenset({
    tokenize.ENCODING, tokenize.NEWLINE, tokenize.NL, tokenize.INDENT,
    tokenize.DEDENT, tokenize.COMMENT, tokenize.ENDMARKER,
})
_STRING_TOKENS = frozenset({tokenize.STRING, tokenize.FSTRING_START})
_DATA_TOKENS = frozenset({tokenize.FSTRING_MIDDLE, tokenize.FSTRING_END})
_TOKEN_TEXTS = {
    tokenize.NUMBER: "N",
    **dict.fromkeys(_STRING_TOKENS, "S"),
}


@dataclass(frozen=True)
class ShapeSpec:
    scope: str
    base: str
    max_chain: int
    clone_min_tokens: int
    clone_similarity: float
    crap_check: str


def _python_shape_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    scope = _optional_string(raw, "scope", "changed", path, full_key)
    if scope not in SCOPES:
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of changed, tree; "
            f"got {scope!r}"
        )
    similarity = _number(
        raw,
        "clone_similarity",
        path,
        f"{full_key}.clone_similarity",
        default=DEFAULT_CLONE_SIMILARITY,
        minimum=0.5,
    )
    if similarity > 1.0:
        raise ConfigError(
            f"{path}: {full_key}.clone_similarity: expected a finite number "
            f"in [0.5, 1.0], got {similarity:g}"
        )
    spec = ShapeSpec(
        scope,
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
        similarity,
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
    is_method: bool = False


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
    paths: tuple[str, ...] = ()


def _is_test_path(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if "tests" in parts:
        return True
    name = parts[-1] if parts else relative
    return name.startswith("test_") or name.endswith("_test.py")


def _collect_definitions(
    nodes: list[ast.AST], prefix: str, path: str,
    found: list[ShapeFunction], in_class: bool = False,
) -> None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = _function_identity(node, prefix)
            function = ShapeFunction(
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
                is_method=in_class,
            )
            found.append(function)
            _collect_definitions(node.body, f"{function.name}.", path, found)
            continue
        if isinstance(node, ast.ClassDef):
            _collect_definitions(
                node.body, f"{prefix}{node.name}.", path, found, True
            )
            continue
        _collect_definitions(
            list(ast.iter_child_nodes(node)), prefix, path, found, in_class
        )


def _dotted(node: ast.AST) -> str | None:
    """The dotted spelling of a called name, so a wrapper names its callee."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


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
                    target.rpartition(".")[2], target, relative, child.lineno,
                    enclosing,
                ))
        _walk_calls(child, enclosing, relative, identities, found)


def _references(node: ast.AST) -> set[str]:
    """The names a test function mentions, by name and by attribute."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
    return found


def _test_functions(
    nodes: list[ast.AST], in_test: bool, found: set[str]
) -> None:
    """Collect the names the test functions mention into found."""
    for node in nodes:
        if not isinstance(
            node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            _test_functions(list(ast.iter_child_nodes(node)), in_test, found)
            continue
        if not isinstance(node, ast.ClassDef) and (
            in_test or node.name.startswith("test")
        ):
            found.update(_references(node))
            continue
        _test_functions(list(node.body), _inside_test(node, in_test), found)


def _inside_test(node: ast.AST, in_test: bool) -> bool:
    """Whether the body of a class or function keeps a walk inside a test."""
    if not isinstance(node, ast.ClassDef):
        return in_test
    return in_test or node.name.startswith("Test") or node.name.endswith(
        ("Test", "Tests")
    )


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


def _after_path(header: str) -> str | None:
    """The after path of a diff header, or None when the diff deletes the file."""
    if header == "/dev/null":
        return None
    if header.startswith('"'):
        raise GateError(
            f"python-shape diff: quoted path {header}; expected an unquoted path"
        )
    return header.removeprefix("b/")


def _added_lines(header: str) -> range:
    """The added line numbers of one zero-context hunk header."""
    after = header.split("+", 1)[1].split(" ", 1)[0]
    start_text, _comma, count_text = after.partition(",")
    start = int(start_text)
    count = int(count_text) if count_text else 1
    return range(start, start + count)


def _hunks(raw: bytes) -> tuple[set[str], dict[str, set[int]]]:
    """The after paths of a zero-context diff and each one's added lines."""
    paths: set[str] = set()
    added: dict[str, set[int]] = {}
    path: str | None = None
    for line in raw.decode("utf-8", "surrogateescape").splitlines():
        if line.startswith("+++ "):
            path = _after_path(line[4:])
            if path is not None:
                paths.add(path)
                added.setdefault(path, set())
        elif path is not None and line.startswith("@@"):
            added[path].update(_added_lines(line))
    return paths, added


def _diff_lines(
    root: Path, base: str, *, changed_paths: frozenset[str] | None = None,
    untracked: frozenset[str] = frozenset(),
) -> Diff:
    """The added line numbers of every changed path, and new whole files."""
    raw = _git(
        root,
        [
            "-c", "core.quotePath=false",
            "diff", "--unified=0", "--no-color", "--no-ext-diff",
            "--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=ACMRTUXB",
            *(["--no-renames"] if changed_paths is not None else []),
            base, "--",
        ],
        "python-shape diff",
    )
    paths, added = _hunks(raw)
    if changed_paths is None:
        untracked = frozenset(_untracked_files(root, "python-shape untracked-file selection"))
        changed_paths = frozenset(paths) | untracked
    return Diff(
        changed_paths,
        {name: frozenset(lines) for name, lines in added.items()},
        untracked,
    )


def _base_functions(
    root: Path, base: str, paths: list[str]
) -> dict[str, dict[str, ShapeFunction]]:
    """The base tree's definitions, by file and qualified name."""
    existing = set(_split_nul(_git(
        root,
        ["ls-tree", "-r", "-z", "--name-only", base, "--"],
        "python-shape base tree",
    )))
    before: dict[str, dict[str, ShapeFunction]] = {}
    for relative in paths:
        if relative not in existing:
            before[relative] = {}
            continue
        data = _git(
            root,
            ["show", f"{base}:{relative}"],
            "python-shape base content",
        )
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError(f"cannot decode {relative}: {error}") from error
        functions: list[ShapeFunction] = []
        _collect_definitions(_parse_tree(relative, source).body, "", relative, functions)
        before[relative] = {
            function.identity: function for function in functions
        }
    return before


def _base_complexities(
    before: dict[str, dict[str, ShapeFunction]],
) -> dict[str, dict[str, int]]:
    """The before tree's definitions reduced to per-function complexity."""
    return {
        relative: {
            identity: function.cc for identity, function in functions.items()
        }
        for relative, functions in before.items()
    }


def _before_complexities(
    root: Path, base: str, paths: list[str]
) -> dict[str, dict[str, int]]:
    """The before tree's per-function complexity, for CPF's comparison."""
    return _base_complexities(_base_functions(root, base, paths))


def _touched(
    spec: ShapeSpec, diff: Diff, function: ShapeFunction
) -> bool:
    """A tree run evaluates every function; a changed run the ones it touches."""
    if spec.scope == "tree" or function.path in diff.whole:
        return True
    return any(
        function.start_line <= line <= function.end_line
        for line in diff.added.get(function.path, frozenset())
    )


def _changed_functions(
    indexes: dict[str, FileIndex],
    before: dict[str, dict[str, ShapeFunction]],
) -> tuple[ShapeFunction, ...]:
    """The definitions that are new or differ from the base tree's.

    A definition is compared with the base revision's definition of the same
    qualified name after 'ast.dump', so a moved function is unchanged while a
    decorator, a removed line or a renamed definition changes it.
    """
    changed: list[ShapeFunction] = []
    for relative, index in indexes.items():
        previous = before.get(relative, {})
        changed.extend(
            function for function in index.functions
            if function.identity not in previous
            or ast.dump(previous[function.identity].node)
            != ast.dump(function.node)
        )
    return tuple(changed)


def _tree_selection(
    indexes: dict[str, FileIndex], diff: Diff,
) -> tuple[tuple[ShapeFunction, ...], tuple[ShapeFunction, ...]]:
    """Every measured function, and the definitions the diff adds."""
    functions = _selected_functions(indexes, lambda function: True)
    added = _selected_functions(
        indexes,
        lambda function: function.path in diff.whole or bool(
            {function.start_line, function.node.lineno}
            & diff.added.get(function.path, frozenset())
        ),
    )
    return functions, added


def _added_functions(
    functions: tuple[ShapeFunction, ...],
    before: dict[str, dict[str, ShapeFunction]],
) -> tuple[ShapeFunction, ...]:
    """The functions whose qualified name is absent from the base tree."""
    return tuple(
        function for function in functions
        if function.identity not in before.get(function.path, {})
    )


def _scan_files(
    context: Any, scoped: list[str], names: set[str]
) -> dict[str, FileIndex]:
    """The files outside the measured scope that mention an added name.

    Every Python file the check selects counts, whatever its name: a helper
    called from a selected program without the .py suffix has two call sites.
    """
    measured = set(scoped)
    indexes: dict[str, FileIndex] = {}
    for relative in context.inventory_files:
        if relative in measured or not is_python_program(
            context.root, relative
        ):
            continue
        source = _read_source(context.root, relative)
        if any(name in source for name in names):
            indexes[relative] = _file_index(relative, source)
    return indexes


def _uses(
    indexes: list[FileIndex], names: set[str]
) -> tuple[dict[str, tuple[CallSite, ...]], frozenset[str]]:
    """The production call sites outside each body, and the names tests mention."""
    calls: dict[str, list[CallSite]] = {}
    tests: set[str] = set()
    for index in indexes:
        tests.update(index.tests)
        for site in index.calls:
            if site.name in names and not _is_test_path(site.path):
                calls.setdefault(site.name, []).append(site)
    return (
        {name: tuple(sites) for name, sites in calls.items()},
        frozenset(tests),
    )


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
    from .checks import _select_files

    selected, _class_names = _select_files(
        context.config, context.check, context.files, context.classes
    )
    production = [
        relative for relative in selected if not _is_test_path(relative)
    ]
    if spec.scope == "tree":
        return production
    return [path for path in production if path in diff.paths]


def _shape_input(
    context: Any, spec: ShapeSpec, limit: float, base: DiffBase,
    *, changed: frozenset[str] | None = None, untracked: frozenset[str] = frozenset(),
) -> ShapeInput:
    """One parse of the measured files, and the indexes every rule reads.

    The CRAP-payoff rule compares against the before tree for files
    touched by the diff. The other rules use the after tree alone.
    """
    tree = spec.scope == "tree"
    if changed is not None and not tree:
        diff = Diff(changed, {}, untracked)
    else:
        diff = _diff_lines(context.root, base.commit, changed_paths=changed, untracked=untracked)
    scoped = _measured_paths(context, spec, diff)
    indexes = {
        path: _file_index(path, _read_source(context.root, path))
        for path in scoped
    }
    base_functions = _base_functions(
        context.root, base.commit, sorted(diff.paths.intersection(scoped))
    )
    if tree:
        functions, added = _tree_selection(indexes, diff)
        candidates = functions
    else:
        functions = _changed_functions(indexes, base_functions)
        added = _added_functions(functions, base_functions)
        candidates = added
    before = _base_complexities(base_functions)
    names = {function.final_name for function in candidates}
    scanned = _scan_files(context, scoped, names)
    parsed = [*indexes.values(), *scanned.values()]
    calls, tests = _uses(parsed, names)
    return ShapeInput(
        functions, before, added, candidates, calls, tests, spec, limit, tuple(scoped),
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


def _single_call_site(
    data: ShapeInput, function: ShapeFunction, *, untested: bool = False
) -> CallSite | None:
    """The function's one call site outside its own body, if it has exactly one."""
    if untested and function.final_name in data.tests:
        return None
    sites = [
        site for site in data.calls.get(function.final_name, ())
        if (site.path, function.start_line <= site.line <= function.end_line)
        != (function.path, True)
    ]
    return sites[0] if len(sites) == 1 else None


def _called_outside(data: ShapeInput, function: ShapeFunction) -> bool:
    """Whether a call outside the function's own body names it."""
    return any(
        site.path != function.path
        or not function.start_line <= site.line <= function.end_line
        for site in data.calls.get(function.final_name, ())
    )


def _own_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """A method's implicit receiver is not one of its own parameters."""
    names = [
        argument.arg
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            node.args.vararg,
            node.args.kwarg,
        ]
        if argument is not None
    ]
    return names[1:] if names[0:1] and names[0] in ("self", "cls") else names


def _arguments(call: ast.Call) -> list[ast.AST] | None:
    """The call's argument values, or None for an unpacked keyword argument."""
    if any(keyword.arg is None for keyword in call.keywords):
        return None
    return [*call.args, *(keyword.value for keyword in call.keywords)]


def _forwarded(
    values: list[ast.AST], own: list[str], constants: int
) -> list[str] | None:
    """The own names the values forward, each once, with every other a constant."""
    named = [value.id for value in values if isinstance(value, ast.Name)]
    forwarding = sorted(named) != sorted(own)
    plain = len(named) + constants != len(values)
    if not named or forwarding or plain:
        return None
    return named


def _wrapper_call(call: ast.Call, own: list[str]) -> Wrapper | None:
    """The wrapper the call makes, when its callee is not an own parameter."""
    callee = _dotted(call.func)
    values = _arguments(call)
    if values is None or callee is None or callee in own:
        return None
    constants = sum(isinstance(value, ast.Constant) for value in values)
    forwarded = _forwarded(values, own, constants)
    if forwarded is None:
        return None
    return Wrapper(callee, tuple(forwarded), constants)


def _body_value(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.AST | None:
    """The value of the body's one expression or return, if it has just one."""
    statements = (
        node.body[1:]
        if node.body and _is_docstring(node.body[0]) else node.body
    )
    if len(statements) != 1:
        return None
    statement = statements[0]
    wanted = (ast.Expr, ast.Return)
    return statement.value if isinstance(statement, wanted) else None


def _wrapper(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Wrapper | None:
    """The call the body forwards every own parameter to, if it is one."""
    value = _body_value(node)
    if isinstance(value, ast.Await):
        value = value.value
    if not isinstance(value, ast.Call):
        return None
    return _wrapper_call(value, _own_names(node))


def _span(function: ShapeFunction) -> str:
    return f"{function.path}:{function.start_line}-{function.end_line}"


def _location(function: ShapeFunction) -> Location:
    return Location(function.path, function.start_line, function.end_line)


def _number_text(value: float) -> str:
    return f"{value:g}"


def _cpf_targets(
    data: ShapeInput
) -> dict[str, tuple[int, ShapeFunction]]:
    """The functions the diff lowered from above the CRAP limit to at most it."""
    targets: dict[str, tuple[int, ShapeFunction]] = {}
    for function in data.functions:
        before = data.before.get(function.path, {}).get(function.identity)
        if before is not None and before > data.limit >= function.cc:
            targets[function.identity] = (before, function)
    return targets


def _uncalled_findings(data: ShapeInput) -> list[Finding]:
    """Each added function no call and no test names."""
    findings = []
    for function in data.candidates:
        if function.final_name in data.tests:
            continue
        if _called_outside(data, function):
            continue
        subject = (
            f"UNCALLED {function.identity} (0 call sites, no direct test; "
            "limit 0 call sites with no direct test; expected a direct test, "
            "a call by name, or the decision kept as data in its one owner)"
        )
        measurement = {
            "rule": "UNCALLED",
            "file": function.path,
            "name": function.name,
            "call_sites": 0,
            "direct_test": False,
        }
        findings.append(Finding(
            subject, 1, _span(function), measurement,
            (_location(function),),
        ))
    return findings


def _cpf_findings(data: ShapeInput) -> list[Finding]:
    """Each added untested single-use helper, and each one inside a payoff target."""
    targets = _cpf_targets(data)
    findings = []
    for helper in data.added:
        site = _single_call_site(data, helper, untested=True)
        if site is None:
            continue
        target = targets.get(site.caller)
        if target is not None:
            before, function = target
            subject = (
                f"CPF {function.identity} CC {before} -> {function.cc}, helper "
                f"{helper.identity} (1 call site, no direct test; limit "
                f"{_number_text(data.limit)} CC; expected the helper to have a direct "
                "test or a second caller, or the function to stay unsplit)"
            )
            measurement = {
                "rule": "CPF",
                "call_sites": 1,
                "direct_test": False,
                "file": function.path,
                "name": function.name,
                "caller": function.identity,
                "helper": helper.identity,
                "helper_file": helper.path,
                "helper_name": helper.name,
                "cc_before": before,
                "cc_after": function.cc,
                "limit": data.limit,
            }
            findings.append(Finding(
                subject, 1, _span(function), measurement,
                (_location(function), _location(helper)),
            ))
            continue
        if not helper.is_method and site.path == helper.path:
            continue
        subject = (
            f"CPF {helper.identity} -> {site.caller} (1 call site, no direct "
            "test; limit 1 call site with no direct test; expected a direct "
            "test, a second caller, or the function to stay with its caller)"
        )
        measurement = {
            "rule": "CPF",
            "call_sites": 1,
            "direct_test": False,
            "file": helper.path,
            "name": helper.name,
            "caller": site.caller,
            "helper": helper.identity,
            "helper_file": helper.path,
            "helper_name": helper.name,
        }
        findings.append(Finding(
            subject, 1, _span(helper), measurement,
            (_location(helper),),
        ))
    return findings


def _ptw_findings(data: ShapeInput) -> list[Finding]:
    """Each candidate that is a pass-through wrapper with one untested call site."""
    findings = []
    for function in data.candidates:
        wrapper = _wrapper(function.node)
        if (
            _single_call_site(data, function) is not None
            and function.final_name not in data.tests
            and wrapper is not None
        ):
            subject = (
                f"PTW-SU {function.identity} -> {wrapper.callee} (forwards "
                f"{', '.join(wrapper.forwarded)}, {wrapper.constants} constants, "
                "1 call site, no direct test; limit 1 call site with no direct "
                "test; expected a direct test, a second caller, or no wrapper)"
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
            findings.append(Finding(
                subject, 1, _span(function), measurement,
                (_location(function),),
            ))
    return findings


def _chain_edges(
    data: ShapeInput, candidates: dict[str, ShapeFunction]
) -> tuple[dict[str, list[str]], list[str]]:
    """The single-caller edges among the candidates, and the chain heads."""
    successors: dict[str, list[str]] = {}
    called: set[str] = set()
    for function in data.candidates:
        site = _single_call_site(data, function)
        if site is not None and site.caller in candidates:
            successors.setdefault(site.caller, []).append(function.identity)
            called.add(function.identity)
    return successors, [item for item in candidates if item not in called]


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


def _scc_findings(data: ShapeInput) -> list[Finding]:
    """One finding per chain of more than max_chain single-caller functions."""
    candidates = {function.identity: function for function in data.candidates}
    successors, heads = _chain_edges(data, candidates)
    findings = []
    for head in heads:
        depth, chain = _chain_path(head, successors, frozenset())
        if depth > data.spec.max_chain:
            limit = data.spec.max_chain
            subject = (
                f"SCC chain depth {len(chain)}: {' -> '.join(chain)} "
                f"(limit {limit}; expected at most {limit} consecutive "
                "single-caller functions)"
            )
            measurement = {
                "rule": "SCC",
                "chain_depth": len(chain),
                "chain": list(chain),
                "limit": limit,
            }
            members = [candidates[identity] for identity in chain]
            findings.append(Finding(
                subject, 1, _span(members[0]), measurement,
                tuple(_location(member) for member in members),
            ))
    return findings


def _normalised_tokens(
    node: ast.FunctionDef | ast.AsyncFunctionDef
) -> tuple[str, ...]:
    """The body's tokens with identifiers, numbers and strings normalised."""
    body = (
        node.body[1:]
        if node.body and _is_docstring(node.body[0]) else node.body
    )
    text = ast.unparse(ast.Module(body=body, type_ignores=[]))
    return tuple(
        _token_text(token)
        for token in tokenize.generate_tokens(io.StringIO(text).readline)
        if token.type not in _SKIPPED_TOKENS
        and token.type not in _DATA_TOKENS
    )


def _token_text(token: tokenize.TokenInfo) -> str:
    """A keyword stays itself; an identifier, number and literal do not.

    Each string literal is one token regardless of spelling, as is each
    number. For f-strings the start represents the whole literal prefix,
    the literal pieces carry data, and the end only closes the string.
    Only the interpolated expressions add structural tokens.
    """
    if token.type == tokenize.NAME and not keyword.iskeyword(token.string):
        return "ID"
    return _TOKEN_TEXTS.get(token.type, token.string)


def _clone_pairs(
    functions: tuple[ShapeFunction, ...],
    tokens: dict[str, tuple[str, ...]], minimum: int,
) -> list[tuple[str, str]]:
    """Each pair of functions that shares one window of minimum tokens."""
    ordered = sorted(
        functions,
        key=lambda function: (
            function.path, function.start_line, function.end_line,
            function.identity,
        ),
    )
    order = {function.identity: index for index, function in enumerate(ordered)}
    buckets: dict[tuple[str, ...], set[str]] = {}
    for function in functions:
        sequence = tokens[function.identity]
        for index in range(len(sequence) - minimum + 1):
            buckets.setdefault(
                sequence[index:index + minimum], set()
            ).add(function.identity)
    pairs: set[tuple[str, str]] = set()
    for identities in buckets.values():
        for pair in itertools.combinations(
            sorted(identities, key=order.__getitem__), 2
        ):
            pairs.add(pair)
    return sorted(pairs, key=lambda pair: (order[pair[0]], order[pair[1]]))


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


def _clone_finding(
    data: ShapeInput, first: ShapeFunction, second: ShapeFunction,
    tokens: dict[str, tuple[str, ...]],
) -> Finding | None:
    """The finding for two candidates whose bodies duplicate a run.

    A pair is left alone when one function contains the other, when the shorter
    body is empty, when the run falls outside the token window, or when the run
    is too small a share of the shorter body.
    """
    if (
        second.name.startswith(first.name + ".")
        or first.name.startswith(second.name + ".")
    ):
        return None
    first_tokens = tokens[first.identity]
    second_tokens = tokens[second.identity]
    shorter = min(len(first_tokens), len(second_tokens))
    run = _longest_common_run(first_tokens, second_tokens)
    ratio = run / max(shorter, 1)
    if (
        not data.spec.clone_min_tokens <= run <= CLONE_MAX_TOKENS
        or ratio < data.spec.clone_similarity
    ):
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
        finding = _clone_finding(
            data, by_identity[first], by_identity[second], tokens
        )
        if finding is not None:
            findings.append(finding)
    return findings


RULES: tuple[Callable[[ShapeInput], list[Finding]], ...] = (
    _uncalled_findings, _cpf_findings, _ptw_findings, _scc_findings,
    _ltc_findings,
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


def _shape_selection(context: Any, data: ShapeInput, start: float) -> Any:
    from .checks import _check_result

    selection = context.selection
    if selection is None:
        return None
    candidates = selection.selected
    reason = "in the requested diff" if data.spec.scope == "changed" else selection.reason
    selection.selected = dict.fromkeys(data.paths, reason)
    selection.left_out = dict.fromkeys(
        sorted(candidates.keys() - selection.selected.keys()), "outside the shape measurement",
    )
    if data.paths:
        return None
    selection.reason = "no files in the shape measurement"
    return _check_result(
        context.check, start, "not_run", execution="not_run", satisfied=True, reason=selection.reason,
    )


def _run_python_shape(context: Any) -> Any:
    from .checks import _configuration_error, _finish_ratchet

    check = context.check
    start = time.monotonic()
    override = context.base_override
    try:
        limit = _crap_limit(context.config, check.spec)
        base = diff_base(context.root, check.spec.base, resolved=override)
        mark_step("python-shape analysis")
        changed = override.changed_paths if override is not None else None
        untracked = override.untracked_paths if override is not None else frozenset()
        data = _shape_input(context, check.spec, limit, base, changed=changed, untracked=untracked)
    except GateError as error:
        return _configuration_error(check, start, context.prefix, error)
    omitted = _shape_selection(context, data, start)
    if omitted is not None:
        return omitted
    mark_step("python-shape rules")
    measured = Domain.of_files(
        sorted({function.path for function in data.functions}),
        "the measured production files",
    )
    return _finish_ratchet(
        check, _findings(data), [], context.prefix, start, measured,
        f"{len(data.functions)} functions measured",
        measurement={
            "functions": len(data.functions),
            "added": len(data.added),
            "base": base.measurement(),
        },
    )
