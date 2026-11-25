"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, location coverage, number display, subject
noun, failure wording and direction rule, whether it produces test counts, the baseline
extras it trusts, its baseline and budget handling, and its per-process setup.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Callable

from . import (
    clones, command, comments, elisp_batch, elisp_crap, elisp_lint, elisp_tests, env_surface,
    module_graph, python_crap, python_mutation, secrets, shell_syntax,
    python_shape, python_tests, ratchet, source_chars, variant_dispatch, verification,
)
from .files import DiffBaseOverride, InventoryClasses, enumerate_entries, source_languages
from .json_input import load_json
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    GateError,
    UnsupportedError,
    _check_keys,
    _config_error,
    _describe,
    _number,
    _optional_string_list,
    _string,
    _string_list,
)
from .runner import Diagnostics, RunResult, RunTimeout, execution_outcome, mark_step, remaining_budget, run
from .tools import tool_binary

if TYPE_CHECKING:
    from .checks import CheckSelection


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
    selection: CheckSelection | None = None


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
    programs = _optional_string_list(raw, "programs", path, f"{key}.programs")
    spec = module_graph.GraphSpec(classes, suites, programs)
    return ParsedSpec(spec, "module-graph/1", ("static",), threshold=0)


def _graph_finding(subject: str, edges: tuple[module_graph.Edge, ...], **measurement: Any) -> ratchet.Finding:
    locations = tuple(ratchet.Location(edge.source, edge.line, edge.line) for edge in edges)
    return ratchet.Finding(subject, 1, ", ".join(map(str, locations)), measurement, locations)


def _graph_cycle_finding(component: list[str], cycle: tuple[module_graph.Edge, ...]) -> ratchet.Finding:
    route = " -> ".join([*(edge.source for edge in cycle), cycle[0].source])
    kinds = {edge.kind for edge in cycle}
    kind = cycle[0].kind if len(kinds) == 1 else "dependency"
    return _graph_finding(
        f"Cyclic {kind} ({route}), component [{', '.join(component)}]", cycle,
        component=component, cycle=[edge.to_json() for edge in cycle],
    )


def _graph_findings(
    cycles: list[module_graph.Cycle], suite_edges: list[module_graph.Edge],
    program_edges: list[module_graph.Edge],
) -> list[ratchet.Finding]:
    findings = [_graph_cycle_finding(component, cycle) for component, cycle in cycles]
    findings.extend(
        _graph_finding(
            f"Suite {edge.kind} ({edge.source} -> {edge.target}) at line {edge.line}",
            (edge,), edge=edge.to_json(),
        )
        for edge in suite_edges
    )
    findings.extend(
        _graph_finding(
            f"Dependency on program ({edge.source} -> {edge.target}) at line {edge.line}",
            (edge,), edge=edge.to_json(),
        )
        for edge in program_edges
    )
    return findings


def _graph_modules(
    context: AdapterContext, spec: module_graph.GraphSpec,
) -> tuple[list[str], list[str], list[str]]:
    unknown = sorted(set(spec.classes) - context.config.classes.keys())
    if unknown:
        key = f"checks.{context.check.id}.classes"
        known = ", ".join(sorted(context.config.classes))
        raise GateError(f"{key}: expected inventory classes from [{known}], got unknown classes {unknown}")
    selected = sorted(path for path in context.files if context.classes.get(path) in spec.classes)
    languages = source_languages(context.root, selected, context.config, context.classes)
    modules: dict[str, list[str]] = {"python": [], "lisp": [], "bash": []}
    for path, language in languages.items():
        if language in modules:
            modules[language].append(path)
    return modules["python"], modules["lisp"], modules["bash"]


def _valid_elisp_payload(record: dict, modules: set[str]) -> bool:
    match record:
        case {"kind": "require", "target": str() as target}:
            return target in modules
        case {"kind": "outside", "message": str()}:
            return True
        case {"kind": "reader-error", "message": str(), "stage": "preparation" | "reader"}:
            return True
    return False


def _valid_elisp_record(record: Any, modules: set[str]) -> bool:
    match record:
        case {"line": int() as line}:
            return type(line) is int and line > 0 and _valid_elisp_payload(record, modules)
    return False


def _graph_elisp_records(records: Any, path: str, modules: set[str]) -> list[dict]:
    if not isinstance(records, list):
        raise ValueError(f"{path}: expected a list of Emacs reader records")
    for index, record in enumerate(records):
        if not _valid_elisp_record(record, modules):
            raise ValueError(f"{path}: invalid Emacs reader record at index {index}")
    return records


def _graph_elisp_report(report: Path, files: list[str], modules: set[str]) -> dict[str, list[dict]]:
    document = load_json(report.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.keys() != set(files):
        raise ValueError("expected an Emacs reader report for each selected file")
    return {path: _graph_elisp_records(document[path], path, modules) for path in files}


def _read_graph_elisp(
    context: AdapterContext, files: list[str], modules: list[str],
) -> dict[str, list[dict]]:
    try:
        with TemporaryDirectory(prefix="qg-module-graph-", dir=context.evidence_dir) as directory:
            manifest = Path(directory) / "files.json"
            report = Path(directory) / "result.json"
            inputs = {"sources": files, "modules": modules}
            manifest.write_text(json.dumps(inputs, ensure_ascii=False), encoding="utf-8")
            mark_step("Emacs module graph")
            command = elisp_batch.batch_command("emacs", None, elisp_batch.MODULE_GRAPH_READER)
            child = run([*command, str(manifest), str(report)], cwd=context.root,
                        budget_seconds=_default_budget(None))
            if not execution_outcome(child.execution).completed or child.returncode != 0:
                status = f"Emacs execution {child.execution}, exit code {child.returncode}"
                raise ValueError(child.error or child.stderr_text.strip() or status)
            return _graph_elisp_report(report, files, set(modules))
    except (OSError, ValueError, RecursionError) as error:
        raise ValueError(f"cannot read Emacs Lisp module graph for {', '.join(files)}: {error}") from error


GraphInputs = tuple[list[str], list[str], list[str]]


@dataclass(frozen=True)
class GraphExtraction:
    inputs: GraphInputs
    modules: list[str]
    edges: list[module_graph.Edge]


def _extract_graph(
    context: AdapterContext, inputs: GraphInputs, reader_findings: list[dict] | None = None,
) -> GraphExtraction:
    python, lisp, shell = inputs
    elisp = _read_graph_elisp(context, lisp, [*python, *lisp, *shell]) if lisp else {}
    if reader_findings is not None:
        reader_findings.extend(
            {"rule": "module-extraction", **row} for row in module_graph.elisp_reader_errors(elisp)
        )
    mark_step("module graph dependencies")
    if remaining_budget(_default_budget(None)) <= 0:
        raise ValueError("module graph dependency extraction deadline exceeded")
    modules, edges, _ = module_graph.dependencies(
        context.root, python, elisp=elisp, shell_modules=shell, parse_shell=GRAPH_SHELL_PARSER,
    )
    return GraphExtraction(inputs, modules, edges)


def module_ownership(
    config: Any, files: list[str], classes: InventoryClasses,
) -> tuple[dict[str, str], list[dict]]:
    return module_graph.resolve_ownership(
        config.modules, files, classes.code_paths, config.capabilities.items(),
    )


def extract_contract_graph(
    root: Path, config: Any, owners: dict[str, str], classes: InventoryClasses, evidence_dir: Path,
    reader_findings: list[dict],
) -> GraphExtraction:
    context = AdapterContext(root, config, None, list(owners), classes, "module-contracts", {}, evidence_dir)
    inputs = _graph_modules(context, module_graph.GraphSpec(tuple(config.classes), ()))
    return _extract_graph(context, inputs, reader_findings)


def module_contract_findings(
    config: Any, owners: dict[str, str], graph: GraphExtraction, tracked_code_paths: frozenset[str],
) -> list[dict]:
    findings = module_graph.interface_findings(config.modules, owners, graph.edges)
    if config.capabilities:
        findings.extend(module_graph.capability_findings(config.capabilities, owners, graph.edges))
    if config.shared_base is not None:
        findings.extend(module_graph.multi_module_findings(owners, graph.edges, tracked_code_paths))
    return findings


def affected_graph(
    root: Path, config: Any, files: list[str], classes: dict[str, str],
    evidence_dir: Path, changed: set[str], contract_graph: GraphExtraction | None = None,
) -> tuple[set[str], dict[str, str], dict[str, str]]:
    spec = module_graph.GraphSpec(tuple(config.classes), ())
    context = AdapterContext(root, config, None, files, classes, "affected scope", {}, evidence_dir)
    inputs = _graph_modules(context, spec)
    graph = contract_graph if contract_graph is not None and contract_graph.inputs == inputs else (
        _extract_graph(context, inputs)
    )
    expanded, affected = module_graph.affected_paths(graph.modules, graph.edges, changed)
    return set(graph.modules), expanded, affected


def _run_module_graph(context: AdapterContext) -> Any:
    from .checks import _finish_ratchet, _ratchet_error

    start = time.monotonic()
    check = context.check
    try:
        python_modules, elisp_modules, shell_modules = _graph_modules(context, check.spec)
        modules = [*python_modules, *elisp_modules, *shell_modules]
        test_sources = frozenset(path for path in modules if python_shape._is_test_path(path))
        elisp = _read_graph_elisp(context, elisp_modules, modules) if elisp_modules else {}
        measurement, cycles, suite_edges, program_edges = module_graph.measure(
            context.root, python_modules, check.spec, elisp=elisp, shell_modules=shell_modules,
            parse_shell=GRAPH_SHELL_PARSER,
            test_sources=test_sources,
        )
    except (GateError, ValueError) as error:
        return _ratchet_error(check, start, context.prefix, error)
    for row in measurement.get("outside_extractor", ()):
        print(f"{context.prefix}: {row['file']}:{row['line']}: {row['message']}", file=sys.stderr)
    findings = _graph_findings(cycles, suite_edges, program_edges)
    return _finish_ratchet(
        check, findings, [], context.prefix, start, ratchet.Domain.all(),
        f"{len(measurement['modules'])} modules measured", measurement=measurement,
    )


@dataclass(frozen=True)
class AllowEntry:
    owner: str
    name: str | None = None
    prefix: str | None = None

    def matches(self, name: str) -> bool:
        if self.prefix is not None:
            return name.startswith(self.prefix)
        return name == self.name


def _env_allow_entry(raw: Any, path: Path, key: str) -> AllowEntry:
    if not isinstance(raw, dict):
        raise _config_error(path, key, "an allowlist table", _describe(raw))
    _check_keys(raw, ("name", "prefix", "owner"), path, key)
    selectors = raw.keys() & {"name", "prefix"}
    if len(selectors) != 1:
        raise _config_error(path, key, "exactly one of name or prefix", repr(raw))
    selector, = selectors
    return AllowEntry(
        _string(raw, "owner", path, f"{key}.owner"),
        **{selector: _string(raw, selector, path, f"{key}.{selector}")},
    )


def _env_surface_spec(raw: dict[str, Any], _root: Path, path: Path, key: str) -> ParsedSpec:
    """Parse an allowlist, defaulting to no allowed names."""
    entries = raw.get("allow", [])
    if not isinstance(entries, list):
        raise _config_error(path, f"{key}.allow", "an array of tables", _describe(entries))
    allowed = tuple(
        _env_allow_entry(entry, path, f"{key}.allow[{index}]")
        for index, entry in enumerate(entries)
    )
    return ParsedSpec(allowed, "env-surface/1", ("static",))


def _env_problems(findings: list[env_surface.Finding], allow: tuple[AllowEntry, ...]) -> list[str]:
    return [
        f"{row.path}:{row.line}: {row.access} {row.name!r}"
        for row in findings if row.name is None or not any(entry.matches(row.name) for entry in allow)
    ]


def _env_failure_reason(errors: list[str], violations: int) -> str | None:
    messages = list(errors)
    if violations:
        messages.append(f"{violations} environment accesses are outside the allowlist or computed")
    return "\n".join(messages) or None


def _run_env_surface(context: AdapterContext) -> Any:
    """Report the complete inventory and fail on unapproved access or unread files."""
    from .checks import _adapter_selection, _check_result

    allow, start, selected, _classes = _adapter_selection(context)
    findings, errors = env_surface.measure(context.root, selected)
    violations = _env_problems(findings, allow)
    for problem in [*errors, *violations]:
        print(f"{context.prefix}: {problem}", file=sys.stderr)
    reason = _env_failure_reason(errors, len(violations))
    return _check_result(
        context.check, start, "fail" if reason else "pass", reason=reason,
        measurement={"findings": [asdict(row) for row in findings]},
    )


def _comments_spec(_raw: dict[str, Any], _root: Path, _path: Path, _key: str) -> ParsedSpec:
    return ParsedSpec(None, "comments/1", ("static",))


def _comments_problems(findings: list[comments.Finding], errors: list[comments.ReadError]) -> list[str]:
    ordered = [(error.path, 0, error.text) for error in errors]
    ordered.extend((row.path, row.line, f"{row.path}:{row.line}: {row.text}") for row in findings)
    ordered.sort(key=lambda item: item[:2])
    return [text for _, _, text in ordered]


def _parse_shell(
    content: bytes, filename: str, required_fields: Callable, *, verify_reproduction: bool = False,
) -> dict[str, Any]:
    mark_step(f"shfmt parsing {filename}")
    try:
        return shell_syntax.parse(
            content, filename, required_fields,
            tool_binary=tool_binary, run=run, execution_outcome=execution_outcome,
            remaining_budget=remaining_budget, verify_reproduction=verify_reproduction,
        )
    except RunTimeout:
        raise
    except (GateError, OSError) as error:
        raise ValueError(f"{filename}: cannot run shfmt: {error}") from error


GRAPH_SHELL_PARSER = partial(_parse_shell, required_fields=lambda _node: {}, verify_reproduction=True)


def _run_comments(context: AdapterContext) -> Any:
    from .checks import _adapter_selection, _check_result

    _spec, start, selected, _classes = _adapter_selection(context)
    languages = source_languages(context.root, selected, context.config, context.classes)
    findings, errors = comments.measure(
        context.root, selected, languages, _parse_shell, remaining_budget,
    )
    problems = _comments_problems(findings, errors)
    for problem in problems:
        print(f"{context.prefix}: {problem}", file=sys.stderr)
    return _check_result(
        context.check, start, "fail" if problems else "pass",
        reason="\n".join(problems) or None,
        measurement={"findings": [asdict(row) for row in findings]},
    )


def _secrets_result(context: AdapterContext, start: float, child: RunResult, budget: int) -> Any:
    from .checks import _check_result

    passed = child.execution == "completed" and child.returncode == 0
    reason = None if passed else child.error or f"Betterleaks exited {child.returncode}"
    return _check_result(
        context.check, start, "pass" if passed else "fail", execution=child.execution,
        reason=reason, diagnostics=child.diagnostics(), budget_seconds=budget,
    )


def _run_secrets(context: AdapterContext) -> Any:
    from .checks import RATCHET_BUDGET_SECONDS, _check_result

    start = time.monotonic()
    try:
        mark_step("verifying Betterleaks")
        binary = tool_binary("betterleaks").resolve(strict=True)
    except (OSError, UnsupportedError) as error:
        print(f"{context.prefix}: {error}", file=sys.stderr)
        return _check_result(context.check, start, "unsupported", execution="error", reason=str(error))

    try:
        with TemporaryDirectory(prefix="qg-secrets-", dir=context.evidence_dir) as directory:
            mark_step("snapshot and scan of Git-selected files")
            root = context.root.resolve()
            selected = [entry.path for entry in enumerate_entries(root) if not entry.gitlink]
            child = secrets.scan(binary, root, Path(directory), selected, RATCHET_BUDGET_SECONDS, run=run)
    except (GateError, OSError, ValueError) as error:
        print(f"{context.prefix}: {error}", file=sys.stderr)
        return _check_result(
            context.check, start, "error", execution="error", reason=str(error),
            diagnostics=Diagnostics(error=str(error)),
        )
    return _secrets_result(context, start, child, RATCHET_BUDGET_SECONDS)


def _affected_test_child(
    context: AdapterContext, plan: Path, command: list[str], environment: dict, start: float,
) -> tuple[Any, str | None]:
    from .checks import _finish_temporary, _temporary_reason, _temporary_test_directory

    temporary = _temporary_test_directory()
    environment["TMPDIR"] = str(temporary)
    mark_step("affected unittest discovery and execution")
    try:
        result = run(
            [*command, str(Path(__file__).with_name("test_shards.py")), "--affected", str(plan)],
            cwd=context.root, env=environment,
            budget_seconds=max(0.0, start + context.check.spec.budget_seconds - time.monotonic()),
        )
    finally:
        temporary_paths = _finish_temporary(temporary)
    return result, _temporary_reason(temporary_paths)


def _affected_test_verdict(report: dict, returncode: int) -> tuple[str, str | None]:
    if report["discovery_errors"]:
        return "fail", report["discovery_errors"][0].splitlines()[0]
    if returncode:
        return "fail", f"command exited {returncode}"
    if report["omitted"]:
        return "not_run", report["selection"]["reason"]
    if not report["executed"]:
        return "fail", "no test executed"
    return "pass", None


def _read_affected_report(path: Path) -> dict:
    with path.open(encoding="utf-8") as journal:
        report = load_json(journal.readline())
        records = {event: [] for event in ("started", "executed", "skipped", "failed")}
        for line in journal:
            if line.endswith("\n"):
                event, name = load_json(line)
                records[event].append(name)
    started = set(records.pop("started"))
    missed = report["selection"]["selected"].keys() - set(records["executed"]) - set(records["skipped"])
    report["not_executed"] = {
        name: "invocation interrupted" if name in started else "the run did not invoke this selected test"
        for name in sorted(missed)
    }
    return {**report, **records}


def _affected_test_report(context: AdapterContext, path: Path, child: Any, start: float) -> Any:
    from .checks import _tests_result

    check, spec, prefix = context.check, context.check.spec, context.prefix
    diagnostics = child.diagnostics()
    failure = python_tests._tests_execution_failure(
        check, spec, child, diagnostics, child.combined_text, prefix, start,
    )
    try:
        report = _read_affected_report(path)
    except (OSError, ValueError) as error:
        if failure is not None:
            return failure
        return _tests_result(
            check, spec, start, prefix, f"unittest produced no discovery and execution report: {error}",
            diagnostics=diagnostics, report=False,
        )
    return _affected_test_check(check, start, child, report, failure)


def _affected_test_check(check: Any, start: float, child: Any, report: dict, failure: Any) -> Any:
    from .checks import _check_result

    outcome, reason = (failure.outcome, failure.reason) if failure else _affected_test_verdict(
        report, child.returncode,
    )
    executed, skipped = len(report["executed"]), len(report["skipped"])
    report.pop("omitted")
    findings = _unittest_findings(sorted(set(report.pop("failed"))))
    fields = {
        "reason": reason, "diagnostics": child.diagnostics(), "budget_seconds": check.spec.budget_seconds,
        "report_fields": report, "findings": findings,
    }
    if outcome == "not_run":
        return _check_result(check, start, outcome, execution="not_run", satisfied=True, **fields)
    return _check_result(check, start, outcome, execution=child.execution, measurement={"tests": executed},
                         tests_ran=executed + skipped, tests_skipped=skipped, **fields)


def _unittest_findings(failed: list[str]) -> list[ratchet.FindingResult]:
    return [
        ratchet.FindingResult(
            subject=name, value=1, bound=None, threshold=0, baseline_reason=None,
            blocking=True, location="unittest",
        )
        for name in failed
    ]


def _affected_test_plan(context: AdapterContext, argv: tuple[str, ...]) -> Path:
    selection = context.selection
    assert selection is not None
    plan = context.evidence_dir / "discovery.json"
    plan.write_text(json.dumps({
        "argv": argv, "paths": selection.test_paths,
        "full": selection.full_suite, "coverage": selection.coverage,
    }), encoding="utf-8")
    return plan


def _affected_unittest(context: AdapterContext, argv: tuple[str, ...]) -> Any:
    from .checks import CheckResult

    start = time.monotonic()
    check, prefix = context.check, context.prefix
    plan = _affected_test_plan(context, argv)
    setup = python_tests._tests_setup(context.root, check, check.spec, start, prefix, context.evidence_dir)
    if isinstance(setup, CheckResult):
        return setup
    data_dir, command = setup
    child, temporary_reason = _affected_test_child(
        context, plan, command, python_tests._test_environment(command), start,
    )
    result = _affected_test_report(context, plan.with_suffix(".result.jsonl"), child, start)
    return _finish_affected_unittest(context, result, data_dir, start, temporary_reason, child)


def _finish_affected_unittest(context: AdapterContext, result: Any, data_dir: Path, start: float,
                              temporary_reason: str | None, child: Any) -> Any:
    from .checks import _finish_test_result

    check, prefix = context.check, context.prefix
    if result.outcome == "pass" and temporary_reason is None:
        evidence = python_tests._tests_evidence(
            check, check.spec, start, prefix, context.evidence_dir, context.root, data_dir,
            result.tests_ran, result.tests_skipped, result.measurement["tests"], result.diagnostics,
        )
        evidence.report_fields = result.report_fields
        return evidence
    return _finish_test_result(result, temporary_reason, prefix, child.combined_text)


def _run_python_tests(context: AdapterContext) -> Any:
    if context.selection is None:
        return python_tests._run_python_tests(context)
    argv = context.check.spec.run
    if python_tests._uses_shard_runner(context.root, argv):
        return _affected_unittest(context, argv[2:])
    context.selection.reason = "full run: custom Python test command is opaque"
    return python_tests._run_python_tests(context)


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
    _run_python_tests,
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
    ("classes", "suites", "programs"),
    _module_graph_spec,
    _run_module_graph,
    location_coverage="complete",
    default_direction="max",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "env_surface",
    ("allow",),
    _env_surface_spec,
    _run_env_surface,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "comments",
    (),
    _comments_spec,
    _run_comments,
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "secrets",
    (),
    lambda _raw, _root, _path, _key: ParsedSpec(None, "secrets/1", ("static",)),
    _run_secrets,
    runs_suite=False,
))
