from __future__ import annotations

import ast
import os.path
import symtable
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from importlib.machinery import PathFinder
from pathlib import Path
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


def _origin(name: str, directories: Sequence[str] | None) -> str | None:
    spec = None
    for part in name.split("."):
        if not directories or not part:
            return None
        spec = PathFinder.find_spec(part, directories)
        if spec is None:
            return None
        directories = spec.submodule_search_locations
    return spec.origin


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
    directories = [str(root)]
    if not node.level:
        directories.append(str(root / path.parent))
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
        directories = [str(root), str(root / path.parent)]
        for alias in node.names:
            yield _origin(alias.name, directories)


_PATH_LOADERS = {
    "runpy.run_path": (0, "path_name"),
    "importlib.util.spec_from_file_location": (1, "location"),
}
_LOADER_NAMES = {target.rsplit(".", 1)[1] for target in _PATH_LOADERS}
_IMPORTS = (ast.Import, ast.ImportFrom)
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_COMP_NAMES = {
    ast.ListComp: "listcomp", ast.SetComp: "setcomp", ast.DictComp: "dictcomp", ast.GeneratorExp: "genexpr",
}
_SCOPE_TYPES = {"type parameter": "type parameters", "TypeVar bound": "type variable"}


def _import_bindings(node: ast.Import | ast.ImportFrom) -> Iterator[tuple[str, str]]:
    if isinstance(node, ast.ImportFrom):
        yield from _from_bindings(node)
        return
    for alias in node.names:
        head = alias.name.split(".", 1)[0]
        yield (alias.asname, alias.name) if alias.asname else (head, head)


def _from_bindings(node: ast.ImportFrom) -> Iterator[tuple[str, str]]:
    base = "." * node.level + (f"{node.module}." if node.module else "")
    for alias in node.names:
        yield alias.asname or alias.name, base + alias.name


def _module_imports(node: ast.AST) -> Iterator[ast.Import | ast.ImportFrom]:
    if isinstance(node, _IMPORTS):
        yield node
    elif not isinstance(node, _DEFINITIONS):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                yield from _module_imports(child)


def _global_writes(table: symtable.SymbolTable) -> Iterator[str]:
    for child in table.get_children():
        yield from (
            symbol.get_name() for symbol in child.get_symbols()
            if symbol.is_declared_global() and (symbol.is_assigned() or symbol.is_imported())
        )
        yield from _global_writes(child)


def _lookup(table: symtable.SymbolTable, name: str) -> symtable.Symbol | None:
    return table.lookup(name) if name in table.get_identifiers() else None


def _callee_parts(node: ast.expr) -> tuple[str, ...]:
    attributes = []
    while isinstance(node, ast.Attribute):
        attributes.append(node.attr)
        node = node.value
    return (node.id, *reversed(attributes)) if isinstance(node, ast.Name) else ()


def _has_unpacking(call: ast.Call) -> bool:
    return any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        arg.arg is None for arg in call.keywords
    )


def _path_operand(call: ast.Call, position: int, keyword: str) -> ast.expr | None:
    if _has_unpacking(call):
        return None
    values = [arg.value for arg in call.keywords if arg.arg == keyword]
    values.extend(call.args[position:position + 1])
    return values[0] if len(values) == 1 else None


def _loader_spellings(head: str, target: str) -> Iterator[str]:
    prefix = target.lstrip(".")
    if prefix.rsplit(".", 1)[-1] in _LOADER_NAMES:
        yield head
    for loader in _PATH_LOADERS:
        if loader.startswith(prefix + "."):
            yield head + loader[len(prefix):]


@dataclass
class _LoaderBindings:
    direct: dict[str, set[str]] = field(default_factory=dict)
    conditional: set[str] = field(default_factory=set)
    spellings: set[str] = field(default_factory=set)
    global_writes: set[str] = field(default_factory=set)

    @classmethod
    def collect(
        cls, tree: ast.Module, table: symtable.SymbolTable, imports: list[ast.Import | ast.ImportFrom],
    ) -> _LoaderBindings:
        bindings = cls(global_writes=set(_global_writes(table)))
        for node in _module_imports(tree):
            for head, target in _import_bindings(node):
                if node in tree.body:
                    bindings.direct.setdefault(head, set()).add(target)
                else:
                    bindings.conditional.add(head)
        for node in imports:
            for head, target in _import_bindings(node):
                bindings.spellings.update(_loader_spellings(head, target))
        return bindings

    def import_refusal(self, head: str) -> str | None:
        if "*" in self.direct or "*" in self.conditional:
            return "a star import can bind the loader name"
        if head in self.conditional:
            return f"{head!r} has a conditional module import"
        if any(target.startswith(".") for target in self.direct.get(head, ())):
            return f"{head!r} has a relative import"
        return None

    def module_refusal(self, table: symtable.SymbolTable, head: str) -> str | None:
        if head in self.global_writes:
            return f"{head!r} is rebound in module globals"
        symbol = _lookup(table, head)
        if symbol is None or not symbol.is_imported():
            return f"{head!r} has no module-level import"
        if symbol.is_assigned():
            return f"{head!r} is assigned or deleted at module scope"
        if len(self.direct.get(head, ())) != 1:
            return f"{head!r} has no unique module-level import"
        return None


def _scope_key(table: symtable.SymbolTable) -> tuple[str, str]:
    kind = table.get_type()
    return _SCOPE_TYPES.get(kind, kind), table.get_name()


def _local_refusal(symbol: symtable.Symbol, head: str) -> str | None:
    if symbol.is_local():
        return f"{head!r} is local to the scope"
    if symbol.is_free() or symbol.is_nonlocal():
        return f"{head!r} is free or nonlocal"
    if not symbol.is_global():
        return f"{head!r} is not global"
    return None


def _iteration_targets(generators: list[ast.comprehension]) -> Iterator[str]:
    for generator in generators:
        for item in ast.walk(generator.target):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                yield item.id


def _private_class(
    scopes: list[symtable.SymbolTable | None], generic_classes: dict[int, set[str]], name: str,
) -> str:
    for table in reversed(scopes):
        if table is None:
            continue
        parameters = generic_classes.get(table.get_id())
        if parameters is not None:
            return table.get_name() if name in parameters else ""
        if table.get_type() == "class":
            return table.get_name()
    return ""


class _PathLoadCalls(ast.NodeVisitor):
    def __init__(self, module: symtable.SymbolTable, bindings: _LoaderBindings, future_annotations: bool):
        self.module = module
        self.scopes: list[symtable.SymbolTable | None] = [module]
        self.bindings = bindings
        self.future_annotations = future_annotations
        self.iteration_names: frozenset[str] = frozenset()
        self.generic_classes: dict[int, set[str]] = {}
        self.annotation_lines: dict[int, int] = {}
        self.calls: list[tuple[ast.Call, tuple[str, ...], str, str | None]] = []

    @contextmanager
    def scope(self, table: symtable.SymbolTable | None) -> Iterator[None]:
        self.scopes.append(table)
        try:
            yield
        finally:
            self.scopes.pop()

    def children(self, kind: str, name: str) -> list[symtable.SymbolTable]:
        current = self.scopes[-1]
        if current is None:
            return []
        return [child for child in current.get_children() if _scope_key(child) == (kind, name)]

    def children_at(self, kind: str, name: str, line: int) -> list[symtable.SymbolTable]:
        return [child for child in self.children(kind, name) if child.get_lineno() == line]

    def visit_nodes(self, nodes: Iterable[ast.AST | None]) -> None:
        for node in nodes:
            if node is not None:
                self.visit(node)

    def visit_scoped(self, kind: str, name: str, line: int, nodes: Iterable[ast.AST | None]) -> None:
        with self.scope(self.unique_child(kind, name, line)):
            self.visit_nodes(nodes)

    def unique_child(self, kind: str, name: str, line: int) -> symtable.SymbolTable | None:
        matches = self.children_at(kind, name, line)
        return matches[0] if len(matches) == 1 else None

    def visit_definition(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.TypeAlias,
        kind: str, name: str, outer: Iterable[ast.AST | None], inner: Iterable[ast.AST | None],
        body: Iterable[ast.AST], annotations: Iterable[ast.AST | None] = (),
    ) -> None:
        self.visit_nodes(outer)
        parameters = self.unique_child("type parameters", name, node.lineno)
        if parameters is not None and isinstance(node, ast.ClassDef):
            self.generic_classes[parameters.get_id()] = {param.name for param in node.type_params}
        scope = self.scope(parameters) if node.type_params else nullcontext()
        with scope:
            self.visit_nodes(node.type_params)
            self.visit_nodes(inner)
            self.visit_annotations(annotations, node.lineno)
            self.visit_scoped(kind, name, node.lineno, body)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = node.args
        outer = [*node.decorator_list, *args.defaults, *args.kw_defaults]
        parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
        annotations = [*(arg.annotation for arg in parameters if arg), node.returns]
        self.visit_definition(node, "function", node.name, outer, (), node.body, annotations)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_annotations(self, nodes: Iterable[ast.AST | None], line: int) -> None:
        matches = self.children_at("annotation", "__annotate__", line)
        if matches or self.future_annotations:
            with self.scope(matches[0] if len(matches) == 1 else None):
                self.visit_nodes(nodes)
        else:
            self.visit_nodes(nodes)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit_nodes((node.target, node.value))
        current = self.scopes[-1]
        line = node.annotation.lineno
        if current is not None:
            line = self.annotation_lines.setdefault(current.get_id(), line)
        self.visit_annotations((node.annotation,), line)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        current = self.scopes[-1]
        if current is not None:
            head = self.compiler_head(node.target.id)
            symbol = _lookup(current, head)
            if current is self.module or (symbol is not None and symbol.is_declared_global()):
                self.bindings.global_writes.add(head)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = [*node.bases, *node.keywords]
        self.visit_definition(node, "class", node.name, node.decorator_list, bases, node.body)

    def visit_TypeAlias(self, node: ast.TypeAlias) -> None:
        self.visit_definition(node, "type alias", node.name.id, (), (), (node.value,))

    def visit_TypeVar(self, node: ast.TypeVar | ast.TypeVarTuple | ast.ParamSpec) -> None:
        self.visit_scoped("type variable", node.name, node.lineno, ast.iter_child_nodes(node))

    visit_TypeVarTuple = visit_ParamSpec = visit_TypeVar

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit_nodes([*node.args.defaults, *node.args.kw_defaults])
        self.visit_scoped("function", "lambda", node.lineno, (node.body,))

    def visit_ListComp(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        first, *rest = node.generators
        self.visit(first.iter)
        nodes = [first.target, *first.ifs, *rest]
        nodes.extend((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,))
        matches = self.comprehension_tables(node)
        if matches or isinstance(node, ast.GeneratorExp):
            with self.scope(matches[0] if len(matches) == 1 else None):
                self.visit_nodes(nodes)
        else:
            self.visit_inlined(node.generators, nodes)

    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    def comprehension_tables(self, node: ast.expr) -> list[symtable.SymbolTable]:
        children = self.children_at("function", _COMP_NAMES[type(node)], node.lineno)
        return [table for table in children if ".0" in table.get_identifiers()]

    def visit_inlined(self, generators: list[ast.comprehension], nodes: list[ast.AST]) -> None:
        previous = self.iteration_names
        self.iteration_names |= frozenset(map(self.compiler_head, _iteration_targets(generators)))
        self.visit_nodes(nodes)
        self.iteration_names = previous

    def visit_Call(self, node: ast.Call) -> None:
        parts = _callee_parts(node.func)
        if parts:
            head = self.compiler_head(parts[0])
            spelling = ".".join((head, *parts[1:]))
            aliases = self.bindings.spellings
            if parts[-1] in _LOADER_NAMES or spelling in aliases or ".".join(parts) in aliases:
                self.calls.append((node, parts, head, self.scope_refusal(head)))
        self.generic_visit(node)

    def compiler_head(self, name: str) -> str:
        if name.startswith("__") and not name.endswith("__"):
            class_name = _private_class(self.scopes, self.generic_classes, name).lstrip("_")
            if class_name:
                return f"_{class_name}{name}"
        return name

    def class_binds(self, head: str) -> bool:
        for table in self.scopes:
            if table is None or table.get_type() != "class":
                continue
            binding = _lookup(table, head)
            if binding is not None and binding.is_local():
                return True
        return False

    def scope_refusal(self, head: str) -> str | None:
        current = self.scopes[-1]
        if current is None:
            return "no unique compiler scope"
        if head in self.iteration_names:
            return f"{head!r} is a local iteration variable"
        symbol = _lookup(current, head)
        if symbol is None:
            return f"{head!r} is absent from the compiler scope"
        if self.class_binds(head):
            return f"{head!r} is bound in a class body"
        return _local_refusal(symbol, head) if current is not self.module else None


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
    if target not in _PATH_LOADERS:
        return None, f"the import resolves to {target!r}, outside the supported loaders"
    value = _path_operand(call, *_PATH_LOADERS[target])
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None, "the path argument must be an unambiguous string literal"
    module = _measured_path(root, source, paths, value.value)
    if module is None:
        return None, f"path {value.value!r} does not resolve to a measured Python file"
    return module, None


def _path_load_outcome(
    root: Path, source: str, paths: dict[str, str], visitor: _PathLoadCalls,
) -> Iterator[tuple[Edge | None, dict | None]]:
    bindings = visitor.bindings
    for call, parts, head, scope_reason in visitor.calls:
        reason = scope_reason or bindings.import_refusal(head)
        reason = reason or bindings.module_refusal(visitor.module, head)
        if reason is None:
            imported, = bindings.direct[head]
            target = ".".join((imported, *parts[1:]))
            module, reason = _resolve_path_load(root, source, paths, call, target)
            if module is not None:
                yield Edge(source, module, call.lineno, "path-load"), None
                continue
        callee = ".".join(parts)
        message = f"unresolved path load {callee}: {reason}"
        yield None, {"file": source, "line": call.lineno, "message": message}


def _path_loads(
    root: Path, source: str, paths: dict[str, str], tree: ast.Module, table: symtable.SymbolTable,
    imports: list[ast.Import | ast.ImportFrom], outside: list[dict],
) -> Iterator[Edge]:
    bindings = _LoaderBindings.collect(tree, table, imports)
    future_annotations = any("__future__.annotations" in targets for targets in bindings.direct.values())
    visitor = _PathLoadCalls(table, bindings, future_annotations)
    visitor.visit(tree)
    for edge, diagnostic in _path_load_outcome(root, source, paths, visitor):
        if diagnostic is not None:
            outside.append(diagnostic)
        if edge is not None:
            yield edge


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
    root: Path, source: str, paths: dict[str, str], literal_paths: dict[str, str], outside: list[dict],
) -> Iterator[Edge]:
    tree, table = _parse_source(root, source)
    imports = [node for node in ast.walk(tree) if isinstance(node, _IMPORTS)]
    yield from {
        Edge(source, paths[origin], node.lineno)
        for node in imports
        for origin in _import_origins(root, source, node, paths)
        if origin in paths
    }
    yield from _path_loads(root, source, literal_paths, tree, table, imports, outside)


def _python_edges(root: Path, modules: list[str], outside: list[dict]) -> Iterator[Edge]:
    paths = {str(root / module): module for module in modules}
    resolved_root = root.resolve()
    literal_paths = {str(resolved_root / module): module for module in modules}
    for module in sorted(modules):
        yield from _source_edges(root, module, paths, literal_paths, outside)


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
    edges = sorted([*_python_edges(root, python_modules, outside), *require_edges])
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
