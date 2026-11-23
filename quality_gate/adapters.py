"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, location coverage, number display, subject
noun, failure wording and direction rule, whether it produces test counts, the baseline
extras it trusts, its baseline and budget handling, and its per-process setup.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import (
    clones, command, elisp_crap, elisp_lint, elisp_tests, module_graph, python_crap, python_mutation,
    python_shape, python_tests, ratchet, source_chars, variant_dispatch, verification,
)
from .files import DiffBaseOverride
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    GateError,
    _config_error,
    _number,
    _optional_string_list,
    _string,
    _string_list,
)


def _default_budget(_spec: Any) -> int:
    from .checks import RATCHET_BUDGET_SECONDS

    return RATCHET_BUDGET_SECONDS


@dataclass(frozen=True)
class AdapterContext:
    """One check's inputs, passed unchanged to its descriptor's runner."""

    root: Path
    config: Any
    check: Any
    files: list[str]
    classes: dict[str, str]
    prefix: str
    prior: dict[str, Any]
    evidence_dir: Path
    base_override: DiffBaseOverride | None = None


@dataclass(frozen=True)
class ParsedSpec:
    """One check's parsed adapter specification and its shared properties."""

    spec: Any
    metric_version: str
    evidence: tuple[str, ...]
    threshold: float | None = None
    baseline: Path | None = None
    requires: str | None = None


@dataclass(frozen=True)
class AdapterDescriptor:
    """Everything the core needs to know about one adapter."""

    name: str
    keys: tuple[str, ...]
    parse: Callable[[dict[str, Any], Path, Path, str], ParsedSpec]
    run: Callable[[AdapterContext], Any]
    location_coverage: str = "none"
    display: Callable[[float], str] = ratchet._number
    subject_noun: str = ""
    failure_wording: str = "metric"
    default_direction: str | None = None
    extras: tuple[str, ...] = ()
    requires_adapter: str | None = None
    requires_tests: bool = False
    budget: Callable[[Any], int] = _default_budget
    entry_direction: Callable[[str, str], str] | None = None
    parse_candidate_inputs: bool = False
    no_tests_hint: str = ""
    runs_suite: bool = field(kw_only=True)

    def allowed_keys(self) -> tuple[str, ...]:
        return (*COMMON_CHECK_KEYS, *self.keys)

    def direction_for_subject(self, subject: str, configured: str) -> str:
        if self.entry_direction is not None:
            return self.entry_direction(subject, configured)
        return self.default_direction or configured

    def required_checks(
        self, requires: str | None, earlier: list[Any]
    ) -> tuple[str, ...]:
        """The earlier check ids a check of this adapter depends on."""
        from .checks import _test_check_dependencies

        if not self.requires_tests:
            return () if requires is None else (requires,)
        return (
            *_test_check_dependencies(requires, earlier),
            *(check.id for check in earlier if check.adapter == "python_crap"),
        )


def _baseline(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> Path | None:
    if "baseline" not in raw:
        return None
    name = _string(raw, "baseline", path, f"{full_key}.baseline")
    if "\x00" in name:
        raise _config_error(
            path, f"{full_key}.baseline", "a path without NUL", repr(name)
        )
    baseline = Path(name)
    if not baseline.is_absolute():
        baseline = root / baseline
    return baseline


def _crap_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str,
    spec_type: Any, version: str,
) -> ParsedSpec:
    requires = _string(raw, "requires", path, f"{full_key}.requires")
    baseline = _baseline(raw, root, path, full_key)
    threshold = _number(
        raw,
        "threshold",
        path,
        f"{full_key}.threshold",
        default=DEFAULT_CRAP_THRESHOLD,
        minimum=0,
    )
    return ParsedSpec(
        spec_type(requires),
        version,
        ("crap",),
        threshold=threshold,
        baseline=baseline,
        requires=requires,
    )


def _module_graph_spec(raw: dict[str, Any], _root: Path, path: Path, key: str) -> ParsedSpec:
    classes = _string_list(raw, "classes", path, f"{key}.classes")
    if not classes:
        raise _config_error(path, f"{key}.classes", "at least one inventory class", "an empty list")
    suites = _optional_string_list(raw, "suites", path, f"{key}.suites")
    return ParsedSpec(module_graph.GraphSpec(classes, suites), "module-graph/1", ("static",), threshold=0)


def _graph_finding(subject: str, edges: tuple[module_graph.Edge, ...], **measurement: Any) -> ratchet.Finding:
    locations = tuple(ratchet.Location(edge.source, edge.line, edge.line) for edge in edges)
    return ratchet.Finding(subject, 1, ", ".join(map(str, locations)), measurement, locations)


def _graph_findings(
    cycles: list[module_graph.Cycle], suite_edges: list[module_graph.Edge]
) -> list[ratchet.Finding]:
    findings = []
    for component, cycle in cycles:
        route = " -> ".join([*(edge.source for edge in cycle), cycle[0].source])
        findings.append(_graph_finding(
            f"Cyclic import ({route}), component [{', '.join(component)}]", cycle,
            component=component, cycle=[edge.to_json() for edge in cycle],
        ))
    findings.extend(
        _graph_finding(
            f"Suite import ({edge.source} -> {edge.target}) at line {edge.line}",
            (edge,), edge=edge.to_json(),
        )
        for edge in suite_edges
    )
    return findings


def _graph_modules(context: AdapterContext, spec: module_graph.GraphSpec) -> list[str]:
    unknown = sorted(set(spec.classes) - context.config.classes.keys())
    if unknown:
        key = f"checks.{context.check.id}.classes"
        known = ", ".join(sorted(context.config.classes))
        raise GateError(f"{key}: expected inventory classes from [{known}], got unknown classes {unknown}")
    return sorted(
        path for path in context.files
        if context.classes.get(path) in spec.classes
        and verification._is_python_program(context.root, path)
    )


def _run_module_graph(context: AdapterContext) -> Any:
    from .checks import _finish_ratchet, _ratchet_error

    start = time.monotonic()
    check = context.check
    try:
        modules = _graph_modules(context, check.spec)
        measurement, cycles, suite_edges = module_graph.measure(context.root, modules, check.spec)
    except (GateError, ValueError) as error:
        return _ratchet_error(check, start, context.prefix, error)
    findings = _graph_findings(cycles, suite_edges)
    return _finish_ratchet(
        check, findings, [], context.prefix, start, ratchet.Domain.all(),
        f"{len(modules)} Python modules measured", measurement=measurement,
    )


def _spec_budget(spec: Any) -> int:
    return spec.budget_seconds


ADAPTERS: dict[str, AdapterDescriptor] = {}


def register_adapter(descriptor: AdapterDescriptor) -> AdapterDescriptor:
    ADAPTERS[descriptor.name] = descriptor
    return descriptor


def remove_adapter(name: str) -> None:
    ADAPTERS.pop(name, None)


def adapter_for(name: str | AdapterDescriptor) -> AdapterDescriptor | None:
    if isinstance(name, AdapterDescriptor):
        return name
    return ADAPTERS.get(name)


def adapter_names() -> tuple[str, ...]:
    return tuple(ADAPTERS)


register_adapter(AdapterDescriptor(
    "command",
    ("run", "budget_seconds", "must_match", "tests_pattern", "skipped_pattern"),
    command._command_spec,
    command._run_command,
    no_tests_hint=" (no tests_pattern)",
    budget=_spec_budget,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "clones",
    ("min_tokens", "baseline"),
    clones._clones_spec,
    clones._run_clones,
    location_coverage="complete",
    subject_noun="clone",
    failure_wording="occurrences",
    extras=("files",),
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "source_chars",
    ("scope", "base", "include_untracked", "allow", "deny", "baseline"),
    source_chars._source_chars_spec,
    source_chars._run_source_chars,
    location_coverage="complete",
    subject_noun="character",
    failure_wording="occurrences",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "python_tests",
    ("run", "tests_pattern", "skipped_pattern", "budget_seconds"),
    python_tests._python_tests_spec,
    python_tests._run_python_tests,
    budget=_spec_budget,
    runs_suite=True,
))
register_adapter(AdapterDescriptor(
    "elisp_tests",
    ("suite", "load_path", "emacs", "budget_seconds"),
    elisp_tests._elisp_tests_spec,
    elisp_tests.run_tests,
    budget=_spec_budget,
    parse_candidate_inputs=True,
    runs_suite=True,
))
register_adapter(AdapterDescriptor(
    "elisp_compile",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
    budget=_spec_budget,
    parse_candidate_inputs=True,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "elisp_checkdoc",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
    budget=_spec_budget,
    parse_candidate_inputs=True,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "python_crap",
    ("requires", "threshold", "baseline"),
    python_crap._python_crap_spec,
    python_crap._run_python_crap,
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="python_tests",
    runs_suite=True,
))
register_adapter(AdapterDescriptor(
    "python_shape",
    (
        "scope", "base", "max_chain", "clone_min_tokens", "clone_similarity",
        "crap_check",
    ),
    python_shape._python_shape_spec,
    python_shape._run_python_shape,
    location_coverage="complete",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "python_mutation",
    ("scope", "base", "mutant_seconds", "function_mutants", "run_seconds"),
    python_mutation._python_mutation_spec,
    python_mutation._run_python_mutation,
    location_coverage="complete",
    budget=python_mutation._budget,
    runs_suite=True,
))
register_adapter(AdapterDescriptor(
    "variant_dispatch",
    ("scope", "base"),
    variant_dispatch._variant_dispatch_spec,
    variant_dispatch._run_variant_dispatch,
    location_coverage="complete",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "elisp_crap",
    ("requires", "threshold", "baseline", "decision_rules"),
    elisp_crap._elisp_crap_spec,
    elisp_crap.run_crap,
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="elisp_tests",
    runs_suite=True,
))
register_adapter(AdapterDescriptor(
    "verification",
    ("requires", "baseline"),
    verification._verification_spec,
    verification._run_verification,
    location_coverage="partial",
    default_direction="max",
    requires_tests=True,
    entry_direction=verification._verification_entry_direction,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "module_graph",
    ("classes", "suites"),
    _module_graph_spec,
    _run_module_graph,
    location_coverage="complete",
    default_direction="max",
    runs_suite=False,
))
