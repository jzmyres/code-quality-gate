from __future__ import annotations

import ast
import os.path
import re
import symtable
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import cache
from importlib._bootstrap_external import _get_supported_file_loaders
from importlib.machinery import FileFinder, ModuleSpec, PathFinder, all_suffixes
from importlib.util import spec_from_file_location
from inspect import signature
from operator import itemgetter
from pathlib import Path
from runpy import run_path
from tokenize import open as open_source
from typing import Any


@dataclass(frozen=True)
class GraphSpec:
    classes: tuple[str, ...]
    suites: tuple[str, ...]
    programs: tuple[str, ...] = ()


@dataclass(frozen=True, order=True)
class Edge:
    source: str
    target: str
    line: int
    kind: str = "import"

    def to_json(self) -> dict[str, str | int]:
        return {"source": self.source, "target": self.target, "line": self.line, "kind": self.kind}


def _pattern_owners(
    modules: dict[str, Any], code_paths: frozenset[str], findings: list[dict],
) -> dict[str, list[str]]:
    matches: dict[str, list[str]] = {path: [] for path in sorted(code_paths)}
    for name, module in sorted(modules.items()):
        owned = set()
        for index, pattern in enumerate(module.files):
            paths = _matched_paths(matches, (pattern,))
            owned.update(paths)
            if not paths:
                key = f"modules.{name}.files[{index}]"
                findings.append({"rule": "unused-pattern", "module": name, "key": key, "pattern": pattern,
                                 "message": f"{key}: pattern {pattern!r} matches no inventoried code file"})
        for path in owned:
            matches[path].append(name)
    return matches


def _entry_point_reason(path: str, name: str, files: set[str], matches: dict[str, list[str]]) -> str | None:
    if path not in files:
        return "absent from inventory"
    if path not in matches:
        return "not an inventoried code file"
    owners = matches[path]
    if owners == [name]:
        return None
    if len(owners) == 1:
        return f"owned by {owners[0]}"
    return f"has multiple module owners: {', '.join(owners)}" if owners else "has no module owner"


def _entry_point_findings(
    key: str, owner: str, paths: tuple[str, ...], present: set[str], matches: dict[str, list[str]],
) -> Iterator[dict]:
    for index, path in enumerate(paths):
        if reason := _entry_point_reason(path, owner, present, matches):
            item = f"{key}.entry_points[{index}]"
            yield {"rule": "invalid-entry-point", "module": owner, "key": item, "file": path,
                   "reason": reason, "message": f"{item}: {path}: {reason}"}


def resolve_ownership(
    modules: dict[str, Any], files: Iterable[str], code_paths: frozenset[str],
    capabilities: Iterable[tuple[str, Any]] = (),
) -> tuple[dict[str, str], list[dict]]:
    findings: list[dict] = []
    matches = _pattern_owners(modules, code_paths, findings)
    ownership = {}
    for path, owners in matches.items():
        if len(owners) == 1:
            ownership[path] = owners[0]
        elif owners:
            findings.append({"rule": "ambiguous-ownership", "file": path, "owners": owners,
                             "message": f"{path}: multiple module owners: {', '.join(owners)}"})
        else:
            findings.append({"rule": "uncovered-file", "file": path,
                             "message": f"{path}: no declared module owner"})
    present = set(files)
    for name, module in sorted(modules.items()):
        findings.extend(_entry_point_findings(f"modules.{name}", name, module.entry_points, present, matches))
    for name, capability in sorted(capabilities):
        findings.extend(_entry_point_findings(
            f"capabilities.{name}", capability.owner, capability.entry_points, present, matches,
        ))
    return ownership, findings


def _failed_interface_conditions(
    modules: dict[str, Any], source: str, target: str, path: str,
) -> list[str]:
    failed = []
    if target not in modules[source].allowed_dependencies:
        failed.append("dependency-not-allowed")
    if path not in modules[target].entry_points:
        failed.append("target-not-entry-point")
    return failed


def _ordered_distinct_edges(edges: Iterable[Edge]) -> Iterator[Edge]:
    distinct = {(edge.source, edge.line, edge.target, edge.kind): edge for edge in edges}
    for key in sorted(distinct):
        yield distinct[key]


def interface_findings(
    modules: dict[str, Any], owners: dict[str, str], edges: Iterable[Edge],
) -> list[dict]:
    findings = []
    for edge in _ordered_distinct_edges(edges):
        source, target = owners[edge.source], owners[edge.target]
        if source == target:
            continue
        if failed := _failed_interface_conditions(modules, source, target, edge.target):
            findings.append({
                "rule": "module-interface", "edge": edge.to_json(),
                "source_module": source, "target_module": target,
                "failed_conditions": failed, "permitted_entry_points": sorted(modules[target].entry_points),
            })
    return findings


_CAPABILITY_CALL_KINDS = frozenset(("path-load", "require", "source", "execute"))


def _capabilities_by_target(capabilities: dict[str, Any]) -> dict[str, list[tuple[str, str]]]:
    by_target: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for name, capability in sorted(capabilities.items()):
        for path in capability.entry_points:
            by_target[path].append((name, capability.owner))
    return by_target


def capability_findings(
    capabilities: dict[str, Any], owners: dict[str, str], edges: Iterable[Edge],
) -> Iterator[dict]:
    by_target = _capabilities_by_target(capabilities)
    calls = (edge for edge in edges if edge.kind in _CAPABILITY_CALL_KINDS)
    for edge in _ordered_distinct_edges(calls):
        source = owners[edge.source]
        for name, owner in by_target.get(edge.target, ()):
            if source != owner:
                yield {
                    "rule": "capability-owner", "file": edge.source, "line": edge.line,
                    "capability": name, "owner": owner, "source_module": source, "edge": edge.to_json(),
                    "message": f"capability {name!r} can only be invoked by its owner {owner!r}",
                }


def multi_module_findings(
    owners: dict[str, str], edges: Iterable[Edge], tracked_code_paths: frozenset[str],
) -> list[dict]:
    dependents: dict[str, set[str]] = {}
    for edge in edges:
        if edge.target in tracked_code_paths:
            dependents.setdefault(edge.target, set()).add(owners[edge.source])
    return [
        {"rule": "multi-module-file", "file": path, "modules": sorted(modules),
         "message": f"{path}: direct dependents in modules {', '.join(sorted(modules))}"}
        for path, modules in sorted(dependents.items()) if len(modules) >= 2
    ]


def _import_names(path: Path) -> Iterator[str]:
    parts = path.with_suffix("").parts
    if not all(part.isidentifier() for part in parts):
        return
    yield ".".join(parts)
    if len(parts) > 1 and path.name == "__init__.py":
        yield ".".join(parts[:-1])


@dataclass(frozen=True)
class PythonImports:
    """Repository paths and identities used by graph and mutation analysis."""

    root: Path
    roots: tuple[str, ...]

    @classmethod
    def from_repository(cls, root: Path, roots: tuple[str, ...]) -> PythonImports:
        canonical_root = root.resolve()
        for relative in roots:
            directory = canonical_root / relative
            if Path(os.path.realpath(directory)) != directory or not directory.is_dir():
                raise ValueError(
                    f"python_import_roots: {relative!r}: expected an existing repository directory"
                )
        return cls(root, roots)

    def directories(self, source: Path | None = None) -> list[str]:
        directories = [str(self.root / directory) for directory in self.roots]
        if source is not None:
            directories.append(str(self.root / source.parent))
        return directories

    def _relative_paths(self, source: Path) -> Iterator[Path]:
        for directory in self.roots:
            if source.is_relative_to(directory):
                yield source.relative_to(directory)

    def package(self, source: Path) -> tuple[str, ...]:
        relative = min(self._relative_paths(source), key=lambda path: len(path.parts), default=None)
        return relative.parts[:-1] if relative is not None else ()

    def _names(self, source: Path) -> Iterator[str]:
        if source.suffix == ".py":
            for relative in self._relative_paths(source):
                yield from _import_names(relative)

    def identities(self, paths: Iterable[str]) -> dict[str, frozenset[str]]:
        providers: dict[str, str] = {}
        identities = {}
        for path in sorted(set(paths)):
            names = frozenset(self._names(Path(path)))
            for name in sorted(names):
                previous = providers.setdefault(name, path)
                if previous != path:
                    raise ValueError(f"ambiguous Python module {name!r}: {previous}, {path}")
            identities[path] = names
        return identities


def _repository_finder() -> Callable[[str, Sequence[str]], ModuleSpec]:
    """Use CPython's ordered lookup with a directory cache for this extraction.

    The returned finder collects fixed namespace portions from the supplied paths.
    """
    loaders = _get_supported_file_loaders()

    class RepositoryFinder(PathFinder):
        _path_importer_cache = staticmethod(cache(
            lambda path: FileFinder(path, *loaders)
        ))

    return RepositoryFinder._get_spec


@dataclass(frozen=True)
class _PythonDiscovery:
    imports: PythonImports
    find: Callable[[str, Sequence[str]], ModuleSpec]

    def spec(self, name: str, directories: Sequence[str] | None) -> ModuleSpec | None:
        for part in name.split("."):
            if not directories:
                return None
            spec = self.find(part, directories)
            directories = spec.submodule_search_locations
        return spec if spec.loader is not None or directories else None

    def origin(self, name: str, directories: Sequence[str] | None) -> str | None:
        if name == "*" or (spec := self.spec(name, directories)) is None:
            return None
        return spec.origin


def _from_base(
    imports: PythonImports, source: Path, node: ast.ImportFrom,
) -> tuple[str, list[str]] | None:
    if not node.level:
        assert node.module is not None
        return node.module, imports.directories(source)
    package = imports.package(source)
    if node.level > len(package):
        return None
    prefix = package[:len(package) - node.level + 1]
    root = source.parents[len(package)]
    return ".".join((*prefix, node.module) if node.module else prefix), [str(imports.root / root)]


def _from_origins(
    discovery: _PythonDiscovery, path: Path, node: ast.ImportFrom, paths: dict[str, str],
) -> Iterator[str | None]:
    base = _from_base(discovery.imports, path, node)
    if base is None or (parent := discovery.spec(*base)) is None:
        return
    for alias in node.names:
        child = discovery.origin(alias.name, parent.submodule_search_locations)
        yield child if child in paths else parent.origin


def _import_origins(
    discovery: _PythonDiscovery, source: str, node: ast.Import | ast.ImportFrom, paths: dict[str, str],
) -> Iterator[str | None]:
    path = Path(source)
    if isinstance(node, ast.ImportFrom):
        yield from _from_origins(discovery, path, node, paths)
    else:
        directories = discovery.imports.directories(path)
        for alias in node.names:
            yield discovery.origin(alias.name, directories)


_PATH_LOADERS = {
    "runpy.run_path": (signature(run_path), "path_name"),
    "importlib.util.spec_from_file_location": (signature(spec_from_file_location), "location"),
}
_LOADER_NAMES = {target.rsplit(".", 1)[1] for target in _PATH_LOADERS}
_LOADER_MODULES = {target.rsplit(".", 1)[0] for target in _PATH_LOADERS}
_LOADER_HEADS = {module.split(".", 1)[0] for module in _LOADER_MODULES}
_IMPORTS = (ast.Import, ast.ImportFrom)
_ANNOTATION_FIELDS = ("annotation", "returns", "bound", "default_value")


def _assigned_loader_symbols(table: symtable.SymbolTable) -> Iterator[tuple[str, str]]:
    tables = [table]
    for scope in tables:
        tables.extend(scope.get_children())
        for head in _LOADER_HEADS.intersection(scope.get_identifiers()):
            symbol = scope.lookup(head)
            if symbol.is_assigned() or symbol.is_parameter():
                yield head, f"{head!r} has another binding in {scope.get_type()} scope"


def _loader_writes(nodes: list[ast.AST]) -> set[str]:
    written = {
        node.id for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    return _LOADER_HEADS & written


def _imported_heads(imports: list[ast.Import | ast.ImportFrom]) -> Counter[str]:
    return Counter(alias.asname or alias.name.split(".", 1)[0] for node in imports for alias in node.names)


def _loader_binding_refusals(
    table: symtable.SymbolTable, nodes: list[ast.AST], imports: list[ast.Import | ast.ImportFrom],
) -> dict[str, str]:
    imported = _imported_heads(imports)
    if imported["*"]:
        return dict.fromkeys(_LOADER_HEADS, "a star import can bind the loader name")
    repeated = {head for head in _LOADER_HEADS if imported[head] > 1}
    return {
        **{head: f"{head!r} has another assignment or deletion binding" for head in _loader_writes(nodes)},
        **dict(_assigned_loader_symbols(table)),
        **{head: f"{head!r} has more than one import binding" for head in repeated},
    }


def _loader_import_positions(tree: ast.Module) -> dict[str, int]:
    return {
        alias.name: index
        for index, node in enumerate(tree.body) if isinstance(node, ast.Import)
        for alias in node.names if alias.asname is None and alias.name in _LOADER_MODULES
    }


def _callee_parts(node: ast.expr) -> tuple[str, ...]:
    attributes = []
    while isinstance(node, ast.Attribute):
        attributes.append(node.attr)
        node = node.value
    return (node.id, *reversed(attributes)) if isinstance(node, ast.Name) else ()


def _path_operand(call: ast.Call, target: str) -> ast.expr | None:
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        raise TypeError("positional argument unpacking")
    keywords = {}
    for arg in call.keywords:
        if arg.arg is None:
            raise TypeError("keyword argument unpacking")
        if arg.arg in keywords:
            raise TypeError(f"repeated keyword argument {arg.arg!r}")
        keywords[arg.arg] = arg.value
    loader_signature, parameter = _PATH_LOADERS[target]
    return loader_signature.bind(*call.args, **keywords).arguments.get(parameter)


def _in_annotation(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    while (parent := parents.get(node)) is not None:
        fields = ("value",) if isinstance(parent, ast.TypeAlias) else _ANNOTATION_FIELDS
        if any(getattr(parent, field, None) is node for field in fields):
            return True
        node = parent
    return False


def _measured_loader_shadows(modules: list[str]) -> dict[str, str]:
    module_files = {head + suffix: head for head in _LOADER_HEADS for suffix in all_suffixes()}
    shadows: dict[str, str] = {}
    for module in modules:
        path = Path(module)
        heads = _LOADER_HEADS.intersection(path.parts[:-1])
        if path.name in module_files:
            heads.add(module_files[path.name])
        for head in heads:
            shadows.setdefault(head, module)
    return shadows


def _loader_shadow(
    discovery: _PythonDiscovery, source: str, head: str, measured: dict[str, str],
) -> str | None:
    if head in measured:
        return measured[head]
    imports = discovery.imports
    spec = discovery.spec(head, imports.directories(Path(source)))
    if spec is None:
        return None
    if spec.origin is not None:
        return os.path.relpath(spec.origin, imports.root)
    assert spec.submodule_search_locations is not None
    return os.path.relpath(next(iter(spec.submodule_search_locations)), imports.root)


def _measured_path(root: Path, source: str, paths: dict[str, str], operand: str) -> str | None:
    path = os.path.join(root, Path(source).parent, operand)
    if not os.path.isfile(path):
        return None
    try:
        return paths.get(os.path.realpath(path, strict=True))
    except (OSError, ValueError):
        return None


def _resolve_path_load(
    root: Path, source: str, paths: dict[str, str], call: ast.Call, target: str,
) -> tuple[str | None, str | None]:
    try:
        value = _path_operand(call, target)
    except TypeError as error:
        return None, f"invalid loader arguments ({error})"
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None, "the path argument must be an unambiguous string literal"
    module = _measured_path(root, source, paths, value.value)
    if module is None:
        return None, f"path {value.value!r} does not resolve to a measured module"
    return module, None


def _loader_import_refusals(
    discovery: _PythonDiscovery, source: str, binding_refusals: dict[str, str],
    shadow_modules: dict[str, str], positions: dict[str, int],
) -> dict[str, str]:
    refusals = {}
    for module in sorted(_LOADER_MODULES):
        head = module.split(".", 1)[0]
        if head in binding_refusals:
            refusals[module] = binding_refusals[head]
        elif module not in positions:
            refusals[module] = f"requires a direct, unaliased top-level import {module}"
        elif (shadow := _loader_shadow(discovery, source, head, shadow_modules)) is not None:
            refusals[module] = f"repository module or package {shadow!r} provides {head!r}"
    return refusals


@dataclass(frozen=True)
class _LoaderReference:
    node: ast.Name | ast.Attribute
    call: ast.Call | None
    statement: int
    target: str
    in_annotation: bool


def _reference_at(
    node: ast.Name | ast.Attribute, parents: dict[ast.AST, ast.AST], index: int,
) -> Iterator[_LoaderReference]:
    name = node.id if isinstance(node, ast.Name) else node.attr
    if name not in _LOADER_NAMES:
        return
    parent = parents.get(node)
    call = parent if isinstance(parent, ast.Call) and parent.func is node else None
    target = ".".join(_callee_parts(node)) or name
    yield _LoaderReference(node, call, index, target, _in_annotation(node, parents))


def _loader_references(tree: ast.Module) -> Iterator[_LoaderReference]:
    for index, statement in enumerate(tree.body):
        nodes = list(ast.walk(statement))
        parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
        for node in nodes:
            if isinstance(node, (ast.Name, ast.Attribute)):
                yield from _reference_at(node, parents, index)


def _loader_reference_refusal(
    reference: _LoaderReference, positions: dict[str, int], import_refusals: dict[str, str],
) -> str | None:
    if reference.in_annotation:
        return "the loader reference is inside an annotation"
    if reference.call is None:
        return "the loader is not called directly"
    if reference.target not in _PATH_LOADERS:
        return "the call does not use a canonical loader spelling"
    module = reference.target.rsplit(".", 1)[0]
    if module in import_refusals:
        return import_refusals[module]
    if positions[module] >= reference.statement:
        return f"import {module} must occur before the enclosing top-level statement"
    return None


def _unresolved(
    file: str, line: int, kind: str, operand: str | None, reason: str, message: str,
) -> dict:
    return {"file": file, "line": line, "kind": kind, "operand": operand,
            "reason": reason, "message": message}


def _path_loads(
    discovery: _PythonDiscovery, source: str, paths: dict[str, str], tree: ast.Module,
    binding_refusals: dict[str, str], shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    positions = _loader_import_positions(tree)
    import_refusals = _loader_import_refusals(discovery, source, binding_refusals, shadow_modules, positions)
    for reference in _loader_references(tree):
        target = reference.target
        reason = _loader_reference_refusal(reference, positions, import_refusals)
        if reason is None:
            assert reference.call is not None
            module, reason = _resolve_path_load(discovery.imports.root, source, paths, reference.call, target)
            if module is not None:
                yield Edge(source, module, reference.node.lineno, "path-load")
                continue
        outside.append(_unresolved(
            source, reference.node.end_lineno, "path-load", target, reason,
            f"unresolved path load {target}: {reason}",
        ))


def _parse_source(root: Path, source: str) -> tuple[ast.Module, symtable.SymbolTable]:
    try:
        with open_source(root / source) as stream:
            text = stream.read()
        tree = ast.parse(text, filename=source)
        table = symtable.symtable(text, source, "exec")
    except (OSError, SyntaxError, UnicodeError) as error:
        raise ValueError(f"{source}: expected readable, valid Python source, got {error}") from error
    return tree, table


def _from_loader_diagnostics(source: str, imports: list[ast.Import | ast.ImportFrom]) -> Iterator[dict]:
    reason = "a from import does not bind the loader module"
    return (
        _unresolved(source, node.lineno, "path-load", alias.name, reason,
                    f"unresolved path load {alias.name}: {reason}")
        for node in imports if isinstance(node, ast.ImportFrom)
        for alias in node.names if alias.name in _LOADER_NAMES
    )


def _source_edges(
    discovery: _PythonDiscovery, source: str, paths: dict[str, str], literal_paths: dict[str, str],
    shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    tree, table = _parse_source(discovery.imports.root, source)
    nodes = list(ast.walk(tree))
    imports = [node for node in nodes if isinstance(node, _IMPORTS)]
    yield from (
        Edge(source, paths[origin], node.lineno)
        for node in imports
        for origin in _import_origins(discovery, source, node, paths)
        if origin in paths
    )
    outside.extend(_from_loader_diagnostics(source, imports))
    binding_refusals = _loader_binding_refusals(table, nodes, imports)
    yield from _path_loads(
        discovery, source, literal_paths, tree, binding_refusals, shadow_modules, outside,
    )


def _python_edges(
    imports: PythonImports, python_modules: list[str], literal_paths: dict[str, str],
    shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    imports.identities(python_modules)
    discovery = _PythonDiscovery(imports, _repository_finder())
    paths = {str(imports.root / module): module for module in python_modules}
    for module in sorted(python_modules):
        yield from _source_edges(discovery, module, paths, literal_paths, shadow_modules, outside)


_SHELL_LITERAL = "Lit"
_SHELL_SINGLE_QUOTE = "SglQuoted"
_SHELL_DOUBLE_QUOTE = "DblQuoted"


_SHELL_SCHEMA = {
    "File": {"Stmts": ["Stmt"]},
    "Stmt": {"Cmd": "", "Redirs": ["Redirect"]},
    "CallExpr": {"Assigns": ["Assign"], "Args": ["Word"]},
    "Assign": {"Index": "", "Value": "Word", "Array": "ArrayExpr"},
    "Redirect": {"Word": "Word", "Hdoc": "Word"},
    "Block": {"Stmts": ["Stmt"]},
    "Subshell": {"Stmts": ["Stmt"]},
    "IfClause": {"Cond": ["Stmt"], "Then": ["Stmt"], "Else": "ElseClause"},
    "ElseClause": {"Cond": ["Stmt"], "Then": ["Stmt"], "Else": "ElseClause"},
    "WhileClause": {"Cond": ["Stmt"], "Do": ["Stmt"]},
    "ForClause": {"Loop": "", "Do": ["Stmt"]},
    "WordIter": {"Items": ["Word"]},
    "CStyleLoop": {"Init": "", "Cond": "", "Post": ""},
    "BinaryCmd": {"X": "Stmt", "Y": "Stmt"},
    "FuncDecl": {"Body": "Stmt"},
    "Word": {"Parts": [""]},
    _SHELL_DOUBLE_QUOTE: {"Parts": [""]},
    "CmdSubst": {"Stmts": ["Stmt"]},
    "ProcSubst": {"Stmts": ["Stmt"]},
    "ParamExp": {"Index": "", "Slice": "Slice", "Repl": "Replace", "Exp": "Expansion"},
    "Slice": {"Offset": "", "Length": ""},
    "Replace": {"Orig": "Word", "With": "Word"},
    "Expansion": {"Op": str, "Word": "Word"},
    "ArithmExp": {"X": ""},
    "ArithmCmd": {"X": ""},
    "BinaryArithm": {"X": "", "Y": ""},
    "UnaryArithm": {"X": ""},
    "ParenArithm": {"X": ""},
    "TestClause": {"X": ""},
    "BinaryTest": {"X": "", "Y": ""},
    "UnaryTest": {"X": ""},
    "ParenTest": {"X": ""},
    "CaseClause": {"Word": "Word", "Items": ["CaseItem"]},
    "CaseItem": {"Patterns": ["Word"], "Stmts": ["Stmt"]},
    "DeclClause": {"Args": ["Assign"]},
    "ArrayExpr": {"Elems": ["ArrayElem"]},
    "ArrayElem": {"Index": "", "Value": "Word"},
    "TimeClause": {"Stmt": "Stmt"},
    "CoprocClause": {"Name": "Word", "Stmt": "Stmt"},
    "LetClause": {"Exprs": [""]},
    "TestDecl": {"Description": "Word", "Body": "Stmt"},
    _SHELL_LITERAL: {"Value": str},
    _SHELL_SINGLE_QUOTE: {},
    "ExtGlob": {},
}

_SHELL_OPTIONAL_FIELDS = {
    ("File", "Stmts"): [],
    ("Stmt", "Cmd"): None,
    ("Stmt", "Redirs"): [],
    ("CallExpr", "Assigns"): [],
    ("CallExpr", "Args"): [],
    ("Assign", "Index"): None,
    ("Assign", "Value"): None,
    ("Assign", "Array"): None,
    ("Redirect", "Hdoc"): None,
    ("Block", "Stmts"): [],
    ("Subshell", "Stmts"): [],
    ("IfClause", "Else"): None,
    ("ElseClause", "Cond"): [],
    ("ElseClause", "Else"): None,
    ("WordIter", "Items"): [],
    ("CStyleLoop", "Init"): None,
    ("CStyleLoop", "Cond"): None,
    ("CStyleLoop", "Post"): None,
    (_SHELL_DOUBLE_QUOTE, "Parts"): [],
    (_SHELL_DOUBLE_QUOTE, "Dollar"): False,
    (_SHELL_SINGLE_QUOTE, "Dollar"): False,
    (_SHELL_SINGLE_QUOTE, "Value"): "",
    ("CmdSubst", "Stmts"): [],
    ("ProcSubst", "Stmts"): [],
    ("ParamExp", "Index"): None,
    ("ParamExp", "Slice"): None,
    ("ParamExp", "Repl"): None,
    ("ParamExp", "Exp"): None,
    ("Slice", "Offset"): None,
    ("Slice", "Length"): None,
    ("Replace", "Orig"): None,
    ("Replace", "With"): None,
    ("Expansion", "Word"): None,
    ("CaseClause", "Items"): [],
    ("CaseItem", "Stmts"): [],
    ("DeclClause", "Args"): [],
    ("ArrayExpr", "Elems"): [],
    ("ArrayElem", "Index"): None,
    ("ArrayElem", "Value"): None,
    ("TimeClause", "Stmt"): None,
    ("CoprocClause", "Name"): None,
}


@dataclass(frozen=True)
class _ShellFields:
    source: str
    content: bytes

    def error(self, detail: str) -> ValueError:
        return ValueError(f"{self.source}: shfmt JSON {detail}")

    def missing(self, field: str, kind: str) -> Any:
        key = kind, field
        if key in _SHELL_OPTIONAL_FIELDS:
            return _SHELL_OPTIONAL_FIELDS[key]
        raise self.error(f"missing field {field}")

    def read(self, node: dict, field: str, expected: type, kind: str = "") -> Any:
        parent, _, key = field.rpartition(".")
        if parent:
            node = self.read(node, parent, dict)
        try:
            value = node[key]
        except KeyError:
            return self.missing(field, kind)
        return self.checked(value, field, expected)

    def checked(self, value: Any, field: str, expected: type) -> Any:
        if type(value) is not expected:
            raise self.error(f"field {field} must be {expected.__name__}")
        if expected is list and any(type(child) is not dict for child in value):
            raise self.error(f"field {field} must contain objects")
        return value


_SHELL_PATH_CHARS = rb"[A-Za-z0-9._/+-]+"
_SHELL_PATH = re.compile(_SHELL_PATH_CHARS)
_SHELL_POSSIBLE_RUN = re.compile(rb"[/{}*?\[]|^~|=~")
_SHELL_DIRECTORY_PARTS = {
    b'"$(dirname "$0")"': {
        "Type": "CmdSubst",
        "Stmts": [{"Cmd": {"Type": "CallExpr", "Args": [
            {"Parts": [{"Type": _SHELL_LITERAL, "Value": "dirname"}]},
            {"Parts": [{"Type": _SHELL_DOUBLE_QUOTE, "Parts": [
                {"Type": "ParamExp", "Short": True, "Param": {"Value": "0"}},
            ]}]},
        ]}}],
    },
    b'"${BASH_SOURCE%/*}"': {
        "Type": "ParamExp",
        "Param": {"Value": "BASH_SOURCE"},
        "Exp": {"Op": "%", "Word": {"Parts": [{"Type": _SHELL_LITERAL, "Value": "/*"}]}},
    },
}
_SHELL_DIRECTORY_PATH = re.compile(
    rb"(" + rb"|".join(map(re.escape, _SHELL_DIRECTORY_PARTS)) + rb")(/" + _SHELL_PATH_CHARS + rb")"
)
_SHELL_LITERAL_LOCATIONS = {"Pos", "End", "ValuePos", "ValueEnd"}
_SHELL_SUBTREE_LOCATIONS = _SHELL_LITERAL_LOCATIONS | {"Position", "Left", "Right", "Rbrace"}
_SHELL_INTERPRETERS = {b"bash", b"sh"}
_ShellWord = tuple[list[dict], bytes]


def _read_shell(
    root: Path, sources: Sequence[str], parse_shell: Callable[[bytes, str], dict] | None,
) -> dict[str, tuple[_ShellFields, dict]]:
    scripts = {}
    for source in sources:
        if parse_shell is None:
            raise ValueError(f"{source}: shell parser is required")
        try:
            content = (root / source).read_bytes()
        except OSError as error:
            raise ValueError(f"cannot read {source}: {error}") from error
        scripts[source] = _ShellFields(source, content), parse_shell(content, source)
    return scripts


def _shell_word(word: dict, fields: _ShellFields) -> _ShellWord:
    parts = fields.read(word, "Parts", list)
    start = fields.read(word, "Pos.Offset", int)
    end = fields.read(word, "End.Offset", int)
    spelling = fields.content[start:end] if 0 <= start < end <= len(fields.content) else b""
    return parts, spelling


def _shell_literal(part: dict, spelling: bytes, fields: _ShellFields) -> bool:
    return (
        fields.read(part, "Type", str) == _SHELL_LITERAL
        and not part.keys() - _SHELL_LITERAL_LOCATIONS - {"Type", "Value"}
        and spelling == fields.read(part, "Value", str).encode()
    )


def _shell_plain_word(word: _ShellWord, fields: _ShellFields) -> bool:
    parts, spelling = word
    return len(parts) == 1 and _shell_literal(parts[0], spelling, fields)


def _shell_subtree_value(actual: Any, expected: Any, fields: _ShellFields) -> bool:
    if isinstance(expected, dict):
        return _shell_subtree(actual, expected, fields)
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _shell_subtree(node, shape, fields) for node, shape in zip(actual, expected, strict=True)
        )
    return actual == expected


def _shell_subtree(actual: dict, expected: dict, fields: _ShellFields) -> bool:
    """Match syntax fields, treating Dollar as a location only on ParamExp."""
    locations = _SHELL_SUBTREE_LOCATIONS | ({"Dollar"} if "Param" in expected else set())
    return actual.keys() - locations == expected.keys() and all(
        _shell_subtree_value(fields.read(actual, key, type(value)), value, fields)
        for key, value in expected.items()
    )


def _shell_directory_target(
    parts: list[dict], prefix: bytes, tail: bytes, fields: _ShellFields,
) -> str | None:
    if len(parts) != 2:
        return None
    quote, literal = parts
    expected = {"Type": _SHELL_DOUBLE_QUOTE, "Parts": [_SHELL_DIRECTORY_PARTS[prefix]]}
    if _shell_subtree(quote, expected, fields) and _shell_literal(literal, tail, fields):
        return "." + tail.decode("ascii")
    return None


def _shell_target(word: _ShellWord, fields: _ShellFields) -> str | None:
    parts, spelling = word
    if _SHELL_PATH.fullmatch(spelling) and _shell_plain_word(word, fields):
        return spelling.decode("ascii")
    if directory := _SHELL_DIRECTORY_PATH.fullmatch(spelling):
        prefix, tail = directory.groups()
        return _shell_directory_target(parts, prefix, tail, fields)
    return None


def _shell_argument_target(word: _ShellWord, fields: _ShellFields) -> str | None:
    if word[1].startswith((b"-", b"+")):
        return None
    return _shell_target(word, fields)


_SHELL_ASSIGNMENT_PREFIX = re.compile(rb"[A-Za-z_][A-Za-z_0-9]*\+?=")
_SHELL_ACTIVE_LITERAL = b" \t\r\n\\'\x22`$*?[]{};|&<>()"


@dataclass
class _SourceWordProof:
    spelling: bytes
    allow_continuation: bool
    assignment_prefix: bool
    offset: int = 0

    def take(self, value: bytes, *, continuations: bool = False) -> bool:
        if not self.spelling.startswith(value, self.offset):
            return False
        self.offset += len(value)
        if continuations:
            self.skip_continuations()
        return True

    def skip_continuations(self) -> None:
        if self.allow_continuation:
            while self.take(b"\\\n"):
                pass

    def literal(self, value: bytes, *, quoted: bool) -> bool:
        for index, byte in enumerate(value):
            active = _unproved_quoted_byte(value, index, byte) if quoted else self.active(byte)
            if active or not self.take(bytes((byte,)), continuations=True):
                return False
        return True

    def active(self, byte: int) -> bool:
        if byte in _SHELL_ACTIVE_LITERAL:
            return True
        if byte != ord("~"):
            return False
        if self.offset == 0:
            return True
        return self.assignment_prefix and self.spelling[self.offset - 1] in b"=:"


def _unproved_quoted_byte(value: bytes, index: int, byte: int) -> bool:
    if byte == ord("\\"):
        return index + 1 == len(value) or value[index + 1] in b'\\`"$\n'
    return byte in b'`"$'


def _source_literal(part: dict, proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    value = fields.read(part, "Value", str).encode()
    return value if proof.literal(value, quoted=False) else None


def _source_single_quote(part: dict, proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    if fields.read(part, "Dollar", bool, _SHELL_SINGLE_QUOTE):
        return None
    value = fields.read(part, "Value", str, _SHELL_SINGLE_QUOTE).encode()
    if b"'" not in value and proof.take(b"'" + value + b"'", continuations=True):
        return value
    return None


def _source_quoted_literals(parts: list[dict], proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    values = []
    for part in parts:
        if fields.read(part, "Type", str) != _SHELL_LITERAL:
            return None
        value = fields.read(part, "Value", str).encode()
        if not proof.literal(value, quoted=True):
            return None
        values.append(value)
    return b"".join(values)


def _source_double_quote(part: dict, proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    if fields.read(part, "Dollar", bool, _SHELL_DOUBLE_QUOTE) or not proof.take(b'"', continuations=True):
        return None
    value = _source_quoted_literals(fields.read(part, "Parts", list, _SHELL_DOUBLE_QUOTE), proof, fields)
    if value is not None and proof.take(b'"', continuations=True):
        return value
    return None


def _source_word_part(part: dict, proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    kind = fields.read(part, "Type", str)
    if kind == _SHELL_LITERAL:
        return _source_literal(part, proof, fields)
    if kind == _SHELL_SINGLE_QUOTE:
        return _source_single_quote(part, proof, fields)
    if kind == _SHELL_DOUBLE_QUOTE:
        return _source_double_quote(part, proof, fields)
    return None


def _source_word_bytes(parts: list[dict], proof: _SourceWordProof, fields: _ShellFields) -> bytes | None:
    values = []
    for part in parts:
        value = _source_word_part(part, proof, fields)
        if value is None:
            return None
        values.append(value)
    if values and proof.offset == len(proof.spelling):
        return b"".join(values)
    return None


def _source_word(word: _ShellWord, fields: _ShellFields, *, head: bool = False) -> bytes | None:
    parts, spelling = word
    if not head and b"\\\n" in spelling:
        return None
    proof = _SourceWordProof(spelling, head, _SHELL_ASSIGNMENT_PREFIX.match(spelling) is not None)
    proof.skip_continuations()
    return _source_word_bytes(parts, proof, fields)


_UNVERIFIED_SOURCE_WORD = "path word is computed or cannot be verified"


def _decoded_source_operand(decoded: bytes | None) -> tuple[str | None, str | None]:
    if decoded is None:
        return None, _UNVERIFIED_SOURCE_WORD
    if decoded.startswith((b"-", b"+")):
        return None, "path operand is an option"
    if not decoded or b"\0" in decoded:
        return None, _UNVERIFIED_SOURCE_WORD
    return decoded.decode("utf-8"), None


def _source_operand(word: _ShellWord, fields: _ShellFields) -> tuple[str | None, str | None]:
    if _SHELL_DIRECTORY_PATH.fullmatch(word[1]):
        target = _shell_target(word, fields)
        return target, None if target is not None else _UNVERIFIED_SOURCE_WORD
    return _decoded_source_operand(_source_word(word, fields))


@dataclass(frozen=True)
class _ShellDependency:
    kind: str
    path: str | None
    operand: str | None
    reason: str | None = None


def _shell_source_call(words: list[_ShellWord], fields: _ShellFields) -> _ShellDependency:
    if len(words) == 1:
        return _ShellDependency("source", None, None, "path operand is missing")
    target, reason = _source_operand(words[1], fields)
    return _ShellDependency("source", target, words[1][1].decode(errors="replace"), reason)


def _shell_execute_call(words: list[_ShellWord], fields: _ShellFields) -> _ShellDependency | None:
    command = words[0]
    _, head = command
    if b"/" in head:
        return _ShellDependency("execute", _shell_target(command, fields), head.decode(errors="replace"))
    if not _shell_plain_word(command, fields) or _SHELL_POSSIBLE_RUN.search(head):
        return _ShellDependency("execute", None, head.decode(errors="replace"))
    if head in _SHELL_INTERPRETERS and len(words) > 1:
        return _ShellDependency(
            "execute", _shell_argument_target(words[1], fields), words[1][1].decode(errors="replace"),
        )
    return None


def _shell_dependency(words: list[_ShellWord], fields: _ShellFields) -> _ShellDependency | None:
    if not words:
        return None
    if _source_word(words[0], fields, head=True) in {b"source", b"."}:
        return _shell_source_call(words, fields)
    return _shell_execute_call(words, fields)


def _shell_children(
    node: dict, kind: str, schema: dict[str, list[str] | str | type], fields: _ShellFields,
) -> Iterator[tuple[dict, str]]:
    for name, role in schema.items():
        if isinstance(role, list):
            yield from ((child, role[0]) for child in fields.read(node, name, list, kind))
        elif isinstance(role, type):
            fields.read(node, name, role, kind)
        elif (child := fields.read(node, name, dict, kind)) is not None:
            yield child, role


def _shell_call(node: dict, fields: _ShellFields) -> Iterator[tuple[str, int, _ShellDependency]]:
    line = fields.read(node, "Pos.Line", int)
    args = fields.read(node, "Args", list, "CallExpr")
    if dependency := _shell_dependency([_shell_word(word, fields) for word in args], fields):
        yield fields.source, line, dependency


def _shell_nodes(tree: dict, fields: _ShellFields) -> Iterator[tuple[dict, str]]:
    pending = [(tree, "")]
    while pending:
        node, kind = pending.pop()
        kind = kind or fields.read(node, "Type", str)
        if kind not in _SHELL_SCHEMA:
            raise fields.error(f"unsupported field Type value {kind!r}")
        yield node, kind
        pending.extend(reversed(list(_shell_children(node, kind, _SHELL_SCHEMA[kind], fields))))


def _shell_dependencies(
    shell: dict[str, tuple[_ShellFields, dict]],
) -> Iterator[tuple[str, int, _ShellDependency]]:
    for fields, tree in shell.values():
        for node, kind in _shell_nodes(tree, fields):
            if kind == "CallExpr":
                yield from _shell_call(node, fields)


def _shell_edges(
    root: Path, shell: dict[str, tuple[_ShellFields, dict]], paths: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    for source, line, call in _shell_dependencies(shell):
        path = call.path
        target = _measured_path(root, source, paths, path) if path else None
        if target is not None:
            yield Edge(source, target, line, call.kind)
            continue
        if path is None:
            detail = "target is outside the parser"
            reason = call.reason or _UNVERIFIED_SOURCE_WORD
        else:
            detail = f"unresolved path {path!r}"
            reason = "path has no measured target"
        outside.append(_unresolved(
            source, line, call.kind, call.operand, reason, f"shell {call.kind}: {detail}",
        ))


def _elisp_records(elisp: dict[str, list[dict]], kind: str) -> Iterator[tuple[str, dict]]:
    return (
        (source, row) for source in sorted(elisp) for row in elisp[source] if row["kind"] == kind
    )


def _graph_edges(
    imports: PythonImports, modules: list[str], python_modules: list[str],
    elisp: dict[str, list[dict]], shell: dict[str, tuple[_ShellFields, dict]], outside: list[dict],
) -> list[Edge]:
    resolved_root = imports.root.resolve()
    paths = {str(resolved_root / module): module for module in modules}
    elisp_edges = (
        Edge(source, row["target"], row["line"], row["kind"])
        for kind in ("require", "path-load") for source, row in _elisp_records(elisp, kind)
    )
    return [
        *_python_edges(imports, python_modules, paths, _measured_loader_shadows(modules), outside),
        *elisp_edges,
        *_shell_edges(imports.root, shell, paths, outside),
    ]


Outgoing = dict[str, dict[str, Edge]]
Incoming = dict[str, set[str]]
Cycle = tuple[list[str], tuple[Edge, ...]]


def _adjacency(modules: list[str], edges: list[Edge]) -> tuple[Outgoing, Incoming]:
    outgoing: Outgoing = {module: {} for module in modules}
    incoming: Incoming = {module: set() for module in modules}
    for edge in edges:
        outgoing[edge.source].setdefault(edge.target, edge)
        incoming[edge.target].add(edge.source)
    return outgoing, incoming


def _finish_from(module: str, outgoing: Outgoing, seen: set[str]) -> Iterator[str]:
    seen.add(module)
    stack = [(module, iter(outgoing[module]))]
    while stack:
        current, neighbors = stack[-1]
        target = next(neighbors, None)
        if target is None:
            yield current
            stack.pop()
        elif target not in seen:
            seen.add(target)
            stack.append((target, iter(outgoing[target])))


def _finish_order(outgoing: Outgoing) -> list[str]:
    seen: set[str] = set()
    finished: list[str] = []
    for module in outgoing:
        if module not in seen:
            finished.extend(_finish_from(module, outgoing, seen))
    return finished


def _components(outgoing: Outgoing, incoming: Incoming) -> list[list[str]]:
    seen: set[str] = set()
    components: list[list[str]] = []
    for module in reversed(_finish_order(outgoing)):
        if module in seen:
            continue
        seen.add(module)
        component = [module]
        for current in component:
            for source in incoming[current] - seen:
                seen.add(source)
                component.append(source)
        if len(component) > 1:
            components.append(sorted(component))
    return sorted(components)


def _cycle_path(last: Edge, parent: dict[str, Edge | None]) -> tuple[Edge, ...]:
    cycle = [last]
    while (previous := parent[cycle[-1].source]) is not None:
        cycle.append(previous)
    return tuple(reversed(cycle))


def _cycle_from(start: str, members: set[str], outgoing: Outgoing) -> tuple[Edge, ...]:
    parent: dict[str, Edge | None] = {start: None}
    queue = deque([start])
    while queue:
        source = queue.popleft()
        neighbors = outgoing[source]
        if source != start and start in neighbors:
            return _cycle_path(neighbors[start], parent)
        for target in sorted(neighbors.keys() & members - parent.keys()):
            parent[target] = neighbors[target]
            queue.append(target)
    return ()


def _shortest_cycle(component: list[str], outgoing: Outgoing) -> tuple[Edge, ...]:
    members = set(component)
    return min(
        (_cycle_from(module, members, outgoing) for module in component),
        key=lambda cycle: (len(cycle), cycle),
    )


def _matched_paths(modules: Iterable[str], patterns: tuple[str, ...]) -> set[str]:
    return {module for module in modules if any(fnmatchcase(module, pattern) for pattern in patterns)}


def _suite_imports(edges: list[Edge], suites: set[str]) -> list[Edge]:
    return [
        edge for edge in edges
        if edge.source != edge.target and edge.source in suites and edge.target in suites
    ]


def _program_dependencies(edges: list[Edge], programs: set[str], test_sources: frozenset[str]) -> list[Edge]:
    exempt_sources = programs | test_sources
    return [edge for edge in edges if edge.target in programs and edge.source not in exempt_sources]


_LOCATED_ORDER = itemgetter("file", "line")


def _outside_diagnostics(rows: list[dict]) -> list[dict]:
    return [
        {key: row[key] for key in ("file", "line", "message")}
        for row in sorted(rows, key=_LOCATED_ORDER)
    ]


@dataclass
class DependencyEvidence:
    unresolved: list[dict] = field(default_factory=list)
    reader_refusals: list[dict] = field(default_factory=list)
    providers: list[dict] = field(default_factory=list)
    python_import_roots: tuple[str, ...] = (".",)

    def report(self) -> dict:
        roots = list(self.python_import_roots) if self.python_import_roots != (".",) else []
        report = {
            "unresolved": [row.copy() for row in sorted(self.unresolved, key=_LOCATED_ORDER)],
            "reader_refusals": [row.copy() for row in self.reader_refusals],
            "providers": [row.copy() for row in self.providers],
            "python_import_roots": roots,
        }
        outside = _outside_diagnostics([*self.unresolved, *self.reader_refusals])
        if outside:
            report["outside_extractor"] = outside
        return report


@dataclass(frozen=True)
class Extraction:
    """Extracted evidence in occurrence order, before report and finding projections."""

    modules: list[str]
    edges: list[Edge]
    evidence: DependencyEvidence

    def report(self) -> dict:
        return {
            "modules": self.modules.copy(),
            "edges": [edge.to_json() for edge in sorted(self.edges)],
            **self.evidence.report(),
        }


def _graph_report(extraction: Extraction, outgoing: Outgoing, incoming: Incoming, findings: int) -> dict:
    return {
        **extraction.report(),
        "fan_in": {module: len(incoming[module]) for module in extraction.modules},
        "fan_out": {module: len(outgoing[module]) for module in extraction.modules},
        "value": findings,
        "threshold": 0,
    }


def elisp_reader_errors(elisp: dict[str, list[dict]]) -> list[dict]:
    return [
        {"file": source, **{key: row[key] for key in ("line", "kind", "stage", "message")}}
        for source, row in _elisp_records(elisp, "reader-error")
    ]


def dependencies(
    root: Path, python_modules: list[str], *,
    elisp: dict[str, list[dict]] | None = None, shell_modules: Sequence[str] = (),
    parse_shell: Callable[[bytes, str], dict] | None = None,
    python_import_roots: tuple[str, ...] = (".",),
) -> Extraction:
    root = root.absolute()
    elisp = elisp or {}
    shell = _read_shell(root, shell_modules, parse_shell)
    modules = sorted([*python_modules, *elisp, *shell])
    unresolved = [
        _unresolved(source, row["line"], row["form"], row["operand"], row["reason"], row["message"])
        for source, row in _elisp_records(elisp, "outside")
    ]
    imports = PythonImports.from_repository(root, python_import_roots)
    edges = _graph_edges(imports, modules, python_modules, elisp, shell, unresolved)
    evidence = DependencyEvidence(
        unresolved, elisp_reader_errors(elisp),
        [{"file": source, "line": row["line"], "feature": row["feature"]}
         for source, row in _elisp_records(elisp, "provider")],
        python_import_roots,
    )
    return Extraction(modules, edges, evidence)


def _affected_seeds(modules: list[str], changed: set[str]) -> dict[str, str]:
    affected = dict.fromkeys(sorted(changed), "changed")
    initializers = (Path(path) for path in sorted(changed) if Path(path).name == "__init__.py")
    for initializer in initializers:
        for module in modules:
            if Path(module).is_relative_to(initializer.parent):
                affected.setdefault(module, f"package initializer {initializer} changed")
    return affected


def affected_paths(
    modules: list[str], edges: list[Edge], changed: set[str],
) -> tuple[dict[str, str], dict[str, str]]:
    _, incoming = _adjacency(modules, edges)
    expanded = _affected_seeds(modules, changed)
    affected = expanded.copy()
    pending = deque(affected)
    while pending:
        path = pending.popleft()
        for dependent in sorted(incoming.get(path, ())):
            if dependent not in affected:
                affected[dependent] = f"depends on {path}"
                pending.append(dependent)
    return expanded, affected


def measure(
    root: Path, python_modules: list[str], spec: GraphSpec, *,
    elisp: dict[str, list[dict]] | None = None, shell_modules: Sequence[str] = (),
    parse_shell: Callable[[bytes, str], dict] | None = None,
    test_sources: frozenset[str] = frozenset(),
    python_import_roots: tuple[str, ...] = (".",),
) -> tuple[dict, list[Cycle], list[Edge], list[Edge]]:
    extraction = dependencies(
        root, python_modules, elisp=elisp, shell_modules=shell_modules, parse_shell=parse_shell,
        python_import_roots=python_import_roots,
    )
    return measure_graph(extraction, spec, test_sources=test_sources)


def measure_graph(
    extraction: Extraction, spec: GraphSpec, *, test_sources: frozenset[str] = frozenset(),
) -> tuple[dict, list[Cycle], list[Edge], list[Edge]]:
    edges = _legacy_edges(extraction.edges)
    modules = extraction.modules
    outgoing, incoming = _adjacency(modules, edges)
    cycles = [
        (component, _shortest_cycle(component, outgoing))
        for component in _components(outgoing, incoming)
    ]
    suite_edges = _suite_imports(edges, _matched_paths(modules, spec.suites))
    programs = _matched_paths(modules, spec.programs)
    program_edges = _program_dependencies(edges, programs, test_sources)
    findings = len(cycles) + len(suite_edges) + len(program_edges)
    return _graph_report(extraction, outgoing, incoming, findings), cycles, suite_edges, program_edges


def _legacy_edges(edges: list[Edge]) -> list[Edge]:
    """Keep the first established kind at a coordinate, ahead of any path load."""
    representatives: dict[tuple[str, str, int], Edge] = {}
    for edge in edges:
        coordinate = edge.source, edge.target, edge.line
        existing = representatives.get(coordinate)
        if existing is None or existing.kind == "path-load":
            representatives[coordinate] = edge
    return [representatives[coordinate] for coordinate in sorted(representatives)]


def _directory(path: str) -> dict:
    return {"path": path, "directories": [], "files": []}


def _module_tree(modules: list[str], languages: dict[str, str | None]) -> dict:
    root = _directory(".")
    directories = {".": root}
    for file in sorted(modules):
        paths = Path(file)
        for parent in reversed(paths.parents):
            path = parent.as_posix()
            if path not in directories:
                node = _directory(path)
                directories[parent.parent.as_posix()]["directories"].append(node)
                directories[path] = node
        directories[paths.parent.as_posix()]["files"].append({"path": file, "language": languages[file]})
    for node in directories.values():
        node["directories"].sort(key=lambda row: row["path"])
    return root


def _cycle_membership(components: list[list[str]]) -> dict[str, int]:
    return {path: index for index, component in enumerate(components) for path in component}


def _internal_group(source: str, target: str, membership: dict[str, int]) -> bool:
    return source in membership and membership[source] == membership.get(target)


def _directory_groups(pairs: list[tuple[str, str, Edge]]) -> dict[tuple[str, str], list[dict]]:
    groups = defaultdict(list)
    for source, target, edge in pairs:
        groups[source, target].append(edge.to_json())
    return groups


def _directory_cycles(components: list[list[str]], pairs: list[tuple[str, str, Edge]]) -> list[dict]:
    membership = _cycle_membership(components)
    cycles = [{"component": component, "edges": []} for component in components]
    for source, target, edge in pairs:
        if source != target and _internal_group(source, target, membership):
            cycles[membership[source]]["edges"].append(edge.to_json())
    return cycles


def _directory_rollup(depth: int, parents: dict[str, tuple[str, ...]], edges: list[Edge]) -> dict:
    ancestors = {path: Path(*parts[:depth]).as_posix() for path, parts in parents.items()}
    directories = sorted(set(ancestors.values()))
    pairs = [(ancestors[edge.source], ancestors[edge.target], edge) for edge in edges]
    groups = _directory_groups(pairs)
    cross = [Edge(source, target, 0) for source, target in groups if source != target]
    components = _components(*_adjacency(directories, cross))
    return {
        "depth": depth, "directories": directories, "cycles": _directory_cycles(components, pairs),
        "edges": [{"source": source, "target": target, "edges": groups[source, target]}
                  for source, target in sorted(groups)],
    }


def _file_cycles(edges: list[Edge], components: list[list[str]]) -> list[tuple[Edge, ...]]:
    membership = _cycle_membership(components)
    groups = defaultdict(list)
    for edge in edges:
        if edge.source == edge.target or _internal_group(edge.source, edge.target, membership):
            groups[edge.source, edge.target, edge.kind].append(edge)
    return [tuple(groups[key]) for key in sorted(groups)]


def measure_tree(
    extraction: Extraction, languages: dict[str, str | None],
) -> tuple[dict, list[tuple[Edge, ...]]]:
    modules = extraction.modules
    edges = sorted(extraction.edges)
    outgoing, incoming = _adjacency(modules, edges)
    cycles = _file_cycles(edges, _components(outgoing, incoming))
    report = _graph_report(extraction, outgoing, incoming, len(cycles))
    parents = {path: Path(path).parts[:-1] for path in modules}
    report["tree"] = _module_tree(modules, languages)
    report["directory_rollups"] = [
        _directory_rollup(depth, parents, edges)
        for depth in range(max(map(len, parents.values()), default=-1) + 1)
    ]
    return report, cycles
