from __future__ import annotations

import ast
from collections import defaultdict, deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from importlib.machinery import PathFinder
from os.path import normpath
from pathlib import Path


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


def _source_edges(root: Path, source: str, paths: dict[str, str]) -> set[Edge]:
    try:
        tree = ast.parse((root / source).read_bytes(), filename=source)
    except (OSError, SyntaxError) as error:
        raise ValueError(f"{source}: expected readable, valid Python source, got {error}") from error
    return {
        Edge(source, paths[origin], node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for origin in _import_origins(root, source, node, paths)
        if origin in paths
    }


def _import_edges(root: Path, modules: list[str]) -> set[Edge]:
    paths = {str(root / module): module for module in modules}
    return {edge for module in sorted(modules) for edge in _source_edges(root, module, paths)}


def _literal_target(root: Path, filename: str, paths: dict[str, str]) -> str | None:
    name = normpath(root / filename)
    if name in paths:
        return paths[name]
    return paths.get(f"{name}.el")


def _elisp_records(elisp: dict[str, list[dict]], kind: str) -> Iterator[tuple[str, dict]]:
    return (
        (source, row) for source in sorted(elisp) for row in elisp[source] if row["kind"] == kind
    )


def _require_target(
    root: Path, row: dict, paths: dict[str, str], providers: dict[str, set[str]],
) -> str | None:
    filename = row["filename"]
    if filename is not None:
        return _literal_target(root, filename, paths)
    candidates = providers.get(row["feature"], ())
    return next(iter(candidates)) if len(candidates) == 1 else None


def _require_edges(root: Path, elisp: dict[str, list[dict]], modules: list[str]) -> set[Edge]:
    paths = {normpath(root / module): module for module in modules}
    providers: dict[str, set[str]] = defaultdict(set)
    for source, row in _elisp_records(elisp, "provide"):
        providers[row["feature"]].add(source)
    edges = set()
    for source, row in _elisp_records(elisp, "require"):
        target = _require_target(root, row, paths, providers)
        if target is not None:
            edges.add(Edge(source, target, row["line"], "require"))
    return edges


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
    elisp: dict[str, list[dict]],
) -> dict:
    report = {
        "modules": modules,
        "edges": [edge.to_json() for edge in edges],
        "fan_in": {module: len(incoming[module]) for module in modules},
        "fan_out": {module: len(outgoing[module]) for module in modules},
        "value": findings,
        "threshold": 0,
    }
    outside = [
        {"file": source, "line": row["line"], "message": row["message"]}
        for source, row in _elisp_records(elisp, "outside")
    ]
    if outside:
        report["outside_extractor"] = outside
    return report


def measure(
    root: Path, python_modules: list[str], spec: GraphSpec, *,
    elisp: dict[str, list[dict]] | None = None, test_sources: frozenset[str] = frozenset(),
) -> tuple[dict, list[Cycle], list[Edge], list[Edge]]:
    root = root.absolute()
    elisp = elisp or {}
    modules = sorted([*python_modules, *elisp])
    edges = sorted(_import_edges(root, python_modules) | _require_edges(root, elisp, modules))
    outgoing, incoming = _adjacency(modules, edges)
    cycles = [
        (component, _shortest_cycle(component, outgoing))
        for component in _components(outgoing, incoming)
    ]
    suite_edges = _suite_imports(edges, _matched_paths(modules, spec.suites))
    programs = _matched_paths(modules, spec.programs)
    program_edges = _program_dependencies(edges, programs, test_sources)
    findings = len(cycles) + len(suite_edges) + len(program_edges)
    measurement = _graph_report(modules, edges, outgoing, incoming, findings, elisp)
    return measurement, cycles, suite_edges, program_edges
