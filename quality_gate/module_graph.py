from __future__ import annotations

import ast
import os.path
import symtable
from collections import Counter, deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from importlib.machinery import ModuleSpec, PathFinder, all_suffixes
from importlib.util import spec_from_file_location
from inspect import signature
from pathlib import Path
from runpy import run_path
from tokenize import open as open_source


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
    kind: str = field(default="import", compare=False)

    def to_json(self) -> dict[str, str | int]:
        return {"source": self.source, "target": self.target, "line": self.line, "kind": self.kind}


def _import_spec(name: str, directories: Sequence[str] | None) -> ModuleSpec | None:
    spec = None
    for part in name.split("."):
        if not directories or not part:
            return None
        spec = PathFinder.find_spec(part, directories)
        if spec is None:
            return None
        directories = spec.submodule_search_locations
    return spec


def _origin(name: str, directories: Sequence[str]) -> str | None:
    spec = _import_spec(name, directories)
    return spec.origin if spec is not None else None


def _import_directories(root: Path, source: Path) -> list[str]:
    return [str(root), str(root / source.parent)]


def _from_base(path: Path, node: ast.ImportFrom) -> str | None:
    package = path.parts[:-1]
    if node.level > len(package):
        return None
    prefix = package[:len(package) - node.level + 1] if node.level else ()
    return ".".join((*prefix, node.module) if node.module else prefix)


def _from_origins(
    root: Path, path: Path, node: ast.ImportFrom, paths: dict[str, str]
) -> Iterator[str | None]:
    base = _from_base(path, node)
    if base is None:
        return
    directories = [str(root)] if node.level else _import_directories(root, path)
    parent = _origin(base, directories)
    for alias in node.names:
        child = None if alias.name == "*" else _origin(f"{base}.{alias.name}", directories)
        yield child if child in paths else parent


def _import_origins(
    root: Path, source: str, node: ast.Import | ast.ImportFrom, paths: dict[str, str]
) -> Iterator[str | None]:
    path = Path(source)
    if isinstance(node, ast.ImportFrom):
        yield from _from_origins(root, path, node, paths)
    else:
        directories = _import_directories(root, path)
        for alias in node.names:
            yield _origin(alias.name, directories)


_PATH_LOADERS = {
    "runpy.run_path": (signature(run_path), "path_name"),
    "importlib.util.spec_from_file_location": (signature(spec_from_file_location), "location"),
}
_LOADER_NAMES = {target.rsplit(".", 1)[1] for target in _PATH_LOADERS}
_LOADER_MODULES = {target.rsplit(".", 1)[0] for target in _PATH_LOADERS}
_LOADER_HEADS = {module.split(".", 1)[0] for module in _LOADER_MODULES}
_IMPORTS = (ast.Import, ast.ImportFrom)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_DEFINITIONS = (*_FUNCTIONS, ast.ClassDef)


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


def _in_local_annotation(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    local_annotation = False
    while (parent := parents.get(node)) is not None:
        if isinstance(parent, ast.AnnAssign) and parent.annotation is node:
            local_annotation = True
        if isinstance(parent, _DEFINITIONS):
            return local_annotation and isinstance(parent, _FUNCTIONS)
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


def _loader_shadow(root: Path, source: str, head: str, measured: dict[str, str]) -> str | None:
    if head in measured:
        return measured[head]
    spec = _import_spec(head, _import_directories(root, Path(source)))
    if spec is None:
        return None
    if spec.origin is not None:
        return os.path.relpath(spec.origin, root)
    assert spec.submodule_search_locations is not None
    return os.path.relpath(next(iter(spec.submodule_search_locations)), root)


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
        return None, f"path {value.value!r} does not resolve to a measured Python file"
    return module, None


def _loader_import_refusals(
    root: Path, source: str, binding_refusals: dict[str, str], shadow_modules: dict[str, str],
    positions: dict[str, int],
) -> dict[str, str]:
    refusals = {}
    for module in sorted(_LOADER_MODULES):
        head = module.split(".", 1)[0]
        if head in binding_refusals:
            refusals[module] = binding_refusals[head]
        elif module not in positions:
            refusals[module] = f"requires a direct, unaliased top-level import {module}"
        elif (shadow := _loader_shadow(root, source, head, shadow_modules)) is not None:
            refusals[module] = f"repository module or package {shadow!r} provides {head!r}"
    return refusals


@dataclass(frozen=True)
class _LoaderReference:
    node: ast.Name | ast.Attribute
    call: ast.Call | None
    statement: int
    target: str
    local_annotation: bool


def _reference_at(
    node: ast.Name | ast.Attribute, parents: dict[ast.AST, ast.AST], index: int,
) -> Iterator[_LoaderReference]:
    name = node.id if isinstance(node, ast.Name) else node.attr
    if name not in _LOADER_NAMES:
        return
    parent = parents.get(node)
    call = parent if isinstance(parent, ast.Call) and parent.func is node else None
    target = ".".join(_callee_parts(node)) or name
    yield _LoaderReference(node, call, index, target, _in_local_annotation(node, parents))


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
    if reference.call is None:
        return "the loader is not called directly"
    if reference.target not in _PATH_LOADERS:
        return "the call does not use a canonical loader spelling"
    if reference.local_annotation:
        return "a function-local variable annotation is never evaluated"
    module = reference.target.rsplit(".", 1)[0]
    if module in import_refusals:
        return import_refusals[module]
    if positions[module] >= reference.statement:
        return f"import {module} must occur before the enclosing top-level statement"
    return None


def _path_loads(
    root: Path, source: str, paths: dict[str, str], tree: ast.Module, binding_refusals: dict[str, str],
    shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    positions = _loader_import_positions(tree)
    import_refusals = _loader_import_refusals(root, source, binding_refusals, shadow_modules, positions)
    for reference in _loader_references(tree):
        target = reference.target
        line = reference.node.lineno
        reason = _loader_reference_refusal(reference, positions, import_refusals)
        if reason is None:
            assert reference.call is not None
            module, reason = _resolve_path_load(root, source, paths, reference.call, target)
            if module is not None:
                yield Edge(source, module, line, "path-load")
                continue
        outside.append({"file": source, "line": line, "message": f"unresolved path load {target}: {reason}"})


def _parse_source(root: Path, source: str) -> tuple[ast.Module, symtable.SymbolTable]:
    try:
        with open_source(root / source) as stream:
            text = stream.read()
        tree = ast.parse(text, filename=source)
        table = symtable.symtable(text, source, "exec")
    except (OSError, SyntaxError, UnicodeError) as error:
        raise ValueError(f"{source}: expected readable, valid Python source, got {error}") from error
    return tree, table


def _source_edges(
    root: Path, source: str, paths: dict[str, str], literal_paths: dict[str, str],
    shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    tree, table = _parse_source(root, source)
    nodes = list(ast.walk(tree))
    imports = [node for node in nodes if isinstance(node, _IMPORTS)]
    yield from {
        Edge(source, paths[origin], node.lineno)
        for node in imports
        for origin in _import_origins(root, source, node, paths)
        if origin in paths
    }
    binding_refusals = _loader_binding_refusals(table, nodes, imports)
    yield from _path_loads(root, source, literal_paths, tree, binding_refusals, shadow_modules, outside)


def _python_edges(
    root: Path, modules: list[str], shadow_modules: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    paths = {str(root / module): module for module in modules}
    resolved_root = root.resolve()
    literal_paths = {str(resolved_root / module): module for module in modules}
    for module in sorted(modules):
        yield from _source_edges(root, module, paths, literal_paths, shadow_modules, outside)


def _elisp_records(elisp: dict[str, list[dict]], kind: str) -> Iterator[tuple[str, dict]]:
    return (
        (source, row) for source in sorted(elisp) for row in elisp[source] if row["kind"] == kind
    )


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


def _matched_paths(modules: list[str], patterns: tuple[str, ...]) -> set[str]:
    return {module for module in modules if any(fnmatchcase(module, pattern) for pattern in patterns)}


def _suite_imports(edges: list[Edge], suites: set[str]) -> list[Edge]:
    return [
        edge for edge in edges
        if edge.source != edge.target and edge.source in suites and edge.target in suites
    ]


def _program_dependencies(edges: list[Edge], programs: set[str], test_sources: frozenset[str]) -> list[Edge]:
    exempt_sources = programs | test_sources
    return [edge for edge in edges if edge.target in programs and edge.source not in exempt_sources]


def _graph_report(
    modules: list[str], edges: list[Edge], outgoing: Outgoing, incoming: Incoming, findings: int,
    outside: list[dict],
) -> dict:
    report = {
        "modules": modules,
        "edges": [edge.to_json() for edge in edges],
        "fan_in": {module: len(incoming[module]) for module in modules},
        "fan_out": {module: len(outgoing[module]) for module in modules},
        "value": findings,
        "threshold": 0,
    }
    if outside:
        report["outside_extractor"] = sorted(outside, key=lambda row: (row["file"], row["line"]))
    return report


def measure(
    root: Path, python_modules: list[str], spec: GraphSpec, *,
    elisp: dict[str, list[dict]] | None = None, test_sources: frozenset[str] = frozenset(),
) -> tuple[dict, list[Cycle], list[Edge], list[Edge]]:
    root = root.absolute()
    elisp = elisp or {}
    modules = sorted([*python_modules, *elisp])
    require_edges = {
        Edge(source, row["target"], row["line"], "require")
        for source, row in _elisp_records(elisp, "require")
    }
    outside = [
        {"file": source, "line": row["line"], "message": row["message"]}
        for source, row in _elisp_records(elisp, "outside")
    ]
    shadows = _measured_loader_shadows(modules)
    edges = sorted([*_python_edges(root, python_modules, shadows, outside), *require_edges])
    outgoing, incoming = _adjacency(modules, edges)
    cycles = [
        (component, _shortest_cycle(component, outgoing))
        for component in _components(outgoing, incoming)
    ]
    unique_edges = list(dict.fromkeys(edges))
    suite_edges = _suite_imports(unique_edges, _matched_paths(modules, spec.suites))
    programs = _matched_paths(modules, spec.programs)
    program_edges = _program_dependencies(unique_edges, programs, test_sources)
    findings = len(cycles) + len(suite_edges) + len(program_edges)
    measurement = _graph_report(modules, edges, outgoing, incoming, findings, outside)
    return measurement, cycles, suite_edges, program_edges
