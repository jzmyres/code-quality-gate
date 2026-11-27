"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, location coverage, number display, subject
noun, failure wording and direction rule, whether it produces test counts, the baseline
extras it trusts, its baseline and budget handling, and its per-process setup.
"""
from __future__ import annotations

import json
import keyword
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Callable, Literal

from . import (
    clones, command, comments, elisp_batch, elisp_crap, elisp_lint, elisp_tests, env_surface,
    module_graph, public_hardware_model, public_vocab, python_crap, python_mutation, secrets, shell_syntax,
    python_shape, python_tests, ratchet, source_chars, variant_dispatch, verification,
)
from .files import (
    DiffBaseOverride, InventoryClasses, _parent_fd, enumerate_entries, git_argv, source_languages,
)
from .json_input import load_json
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    ConfigError,
    GateError,
    UnsupportedError,
    _STRING,
    _TABLE,
    _check_keys,
    _config_error,
    _describe,
    _integer,
    _number,
    _optional_string_list,
    _read_scalar,
    _read_value,
    _string,
    _string_list,
    _unique,
    _validate_exact_path,
)
from .runner import Diagnostics, RunResult, RunTimeout, execution_outcome, mark_step, remaining_budget, run
from .tools import tool_binary

is_files_argument = command.is_files_argument

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
    inventory_files: list[str] = field(kw_only=True)


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
    file_selection: Literal["expanded", "affected"] | None = None
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
    context: AdapterContext, spec: module_graph.GraphSpec, candidates: list[str],
) -> tuple[list[str], list[str], list[str]]:
    unknown = sorted(set(spec.classes) - context.config.classes.keys())
    if unknown:
        key = f"checks.{context.check.id}.classes"
        known = ", ".join(sorted(context.config.classes))
        raise GateError(f"{key}: expected inventory classes from [{known}], got unknown classes {unknown}")
    selected = sorted(path for path in candidates if context.classes.get(path) in spec.classes)
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
        python_import_roots=context.config.python_import_roots,
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
    reader_findings: list[dict], *, inventory_files: list[str],
) -> GraphExtraction:
    context = AdapterContext(
        root, config, None, list(owners), classes, "module-contracts", {}, evidence_dir,
        inventory_files=inventory_files,
    )
    inputs = _graph_modules(context, module_graph.GraphSpec(tuple(config.classes), ()), context.files)
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
    context = AdapterContext(
        root, config, None, files, classes, "affected scope", {}, evidence_dir, inventory_files=files,
    )
    inputs = _graph_modules(context, spec, context.inventory_files)
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
        python_modules, elisp_modules, shell_modules = _graph_modules(
            context, check.spec, context.inventory_files,
        )
        modules = [*python_modules, *elisp_modules, *shell_modules]
        test_sources = frozenset(path for path in modules if python_shape._is_test_path(path))
        elisp = _read_graph_elisp(context, elisp_modules, modules) if elisp_modules else {}
        measurement, cycles, suite_edges, program_edges = module_graph.measure(
            context.root, python_modules, check.spec, elisp=elisp, shell_modules=shell_modules,
            parse_shell=GRAPH_SHELL_PARSER,
            test_sources=test_sources,
            python_import_roots=context.config.python_import_roots,
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


_PROVENANCE_RECORD_FIELDS = ("record", "pointer")
_PROVENANCE_FIELDS = (*_PROVENANCE_RECORD_FIELDS, "payload", "payload_sha256")
_GZIP_DIGEST_FIELDS = ("compressed_sha256", "decoded_sha256")
_GIT_PAYLOAD_FIELDS = ("path", "commit", "blob", "size")
_GZIP_PAYLOAD_FIELDS = ("path", "compressed_sha256", "decoded_size")
_PUBLIC_VOCABULARY_FIELDS = (
    "path", "published_url", "published_revision", "published_sha256", "published_size", "pointers",
)
_PUBLIC_ARCHIVE_FIELDS = ("compressed_sha256", "compressed_size")
_PUBLIC_MODEL_KEY = "public_hardware_model_v1"
_MODEL_BINDING_FIELDS = ("match_start", "match_end", "catalogue")
_PUBLIC_MODEL_FIELDS = (*_PROVENANCE_RECORD_FIELDS, *_MODEL_BINDING_FIELDS, "decoded_sha256")
_PYTHON_MODEL_FIELDS = ("record", *_MODEL_BINDING_FIELDS, "role", "identifier", "source_sha256")
_MODEL_CATALOGUE_FIELDS = ("payload", "sha256", "literal_start", "literal_end")


def _valid_python_pointer(parts: tuple[str, ...]) -> bool:
    return (
        len(parts) == 2
        and parts[0].isascii()
        and parts[0].isidentifier()
        and not keyword.iskeyword(parts[0])
        and bool(parts[1])
    )


def _read_pointer(pointer: str, path: Path, where: str, *, python: bool) -> tuple[str, ...]:
    if not pointer.startswith("/") or re.search(r"~(?:[^01]|$)", pointer):
        raise _config_error(path, where, "a non-root JSON Pointer", "invalid syntax")
    parts = tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:])
    if python and not _valid_python_pointer(parts):
        raise _config_error(path, where, "/ASSIGNMENT/literal-key", "invalid Python pointer")
    return parts


def _provenance_digest(row: dict[str, Any], field: str, path: Path, where: str) -> str:
    key = f"{where}.{field}"
    digest = _string(row, field, path, key)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise _config_error(path, key, "64 lowercase hex digits", "invalid value")
    return digest


def _gzip_digests(row: dict[str, Any], record: str, path: Path, where: str) -> secrets.GzipDigests | None:
    if record.endswith(".json.gz"):
        compressed, decoded = (_provenance_digest(row, field, path, where) for field in _GZIP_DIGEST_FIELDS)
        return secrets.GzipDigests(compressed, decoded)
    if any(field in row for field in _GZIP_DIGEST_FIELDS):
        raise _config_error(path, where, "gzip digest pins only for a .json.gz record", "unexpected pins")
    return None


def _git_payload(raw: dict[str, Any], path: Path, where: str) -> secrets.GitPayload:
    _check_keys(raw, _GIT_PAYLOAD_FIELDS, path, where)
    name, commit, blob = (
        _string(raw, field, path, f"{where}.{field}") for field in _GIT_PAYLOAD_FIELDS[:3]
    )
    _validate_exact_path(path, f"{where}.path", name)
    valid_ids = all(secrets.FULL_GIT_OBJECT.fullmatch(value) for value in (commit, blob))
    if not valid_ids or len(commit) != len(blob):
        raise _config_error(
            path, where, "full lowercase commit and blob IDs in the same Git object format", "invalid IDs",
        )
    size = _integer(raw, "size", path, f"{where}.size", minimum=0, maximum=secrets.MAX_GIT_PAYLOAD_BYTES)
    return secrets.GitPayload(name, commit, blob, size)


def _gzip_payload(raw: dict[str, Any], path: Path, where: str) -> secrets.GzipPayload:
    _check_keys(raw, _GZIP_PAYLOAD_FIELDS, path, where)
    name = _string(raw, "path", path, f"{where}.path")
    _validate_exact_path(path, f"{where}.path", name)
    compressed = _provenance_digest(raw, "compressed_sha256", path, where)
    size = _integer(
        raw, "decoded_size", path, f"{where}.decoded_size", minimum=0,
        maximum=secrets.MAX_GZIP_PAYLOAD_BYTES,
    )
    return secrets.GzipPayload(name, compressed, size)


def _provenance_payload(
    row: dict[str, Any], path: Path, where: str, *, python: bool,
) -> secrets.Payload:
    value = row.get("payload")
    key = f"{where}.payload"
    if isinstance(value, dict):
        if value.keys() & {"compressed_sha256", "decoded_size"}:
            return _gzip_payload(value, path, key)
        if python:
            raise _config_error(path, key, "a tracked raw or gzip payload for a .py record", "Git object")
        return _git_payload(value, path, key)
    name = _string(row, "payload", path, key)
    _validate_exact_path(path, key, name)
    return name


def _parse_provenance(row: Any, path: Path, where: str) -> secrets.Provenance:
    if not isinstance(row, dict):
        raise _config_error(path, where, "a table", type(row).__name__)
    _check_keys(row, (*_PROVENANCE_FIELDS, *_GZIP_DIGEST_FIELDS), path, where)
    record, pointer_text = (
        _string(row, field, path, f"{where}.{field}") for field in ("record", "pointer")
    )
    _validate_exact_path(path, f"{where}.record", record)
    python = record.endswith(".py")
    payload = _provenance_payload(row, path, where, python=python)
    payload_path = payload if isinstance(payload, str) else payload.path
    if not record.endswith((".json", ".json.gz", ".py")) or record == payload_path:
        raise _config_error(
            path, where, "a .json, .json.gz or .py record and a separate payload", "invalid paths",
        )
    digest = _provenance_digest(row, "payload_sha256", path, where)
    pointer = _read_pointer(pointer_text, path, f"{where}.pointer", python=python)
    return secrets.Provenance(record, pointer, payload, digest, _gzip_digests(row, record, path, where))


def _secrets_provenance(raw: dict[str, Any], path: Path, key: str) -> tuple[secrets.Provenance, ...]:
    name = f"{key}.sha256_provenance"
    rows = raw.get("sha256_provenance", [])
    if not isinstance(rows, list):
        raise _config_error(path, name, "an array of tables", type(rows).__name__)
    declarations = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for index, row in enumerate(rows):
        where = f"{name}[{index}]"
        declaration = _parse_provenance(row, path, where)
        _unique(
            seen, (declaration.record, declaration.pointer), path, where,
            "a unique record and pointer", "duplicate", _config_error,
        )
        declarations.append(declaration)
    return tuple(declarations)


def _published_release(row: dict[str, Any], path: Path, where: str) -> tuple[str, str]:
    url = _string(row, "published_url", path, f"{where}.published_url")
    revision = _string(row, "published_revision", path, f"{where}.published_revision")
    if not secrets.FULL_GIT_OBJECT.fullmatch(revision):
        raise _config_error(path, f"{where}.published_revision", "a full lowercase revision ID", "invalid ID")
    parts = url.removeprefix("https://").split("/")[1:]
    if not (
        re.fullmatch(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._@+-]+)+", url)
        and revision in parts[:-1]
        and parts[-1] == "tokenizer.json"
        and not {".", ".."}.intersection(parts)
    ):
        raise _config_error(
            path, where, "an HTTPS tokenizer.json URL containing the full revision", "invalid URL",
        )
    return url, revision


def _published_keys(row: dict[str, Any], path: Path, where: str) -> frozenset[str]:
    key = f"{where}.pointers"
    pointers = _string_list(row, "pointers", path, key)
    if not 1 <= len(pointers) <= public_vocab.MAX_POINTERS:
        raise _config_error(path, key, f"1 to {public_vocab.MAX_POINTERS} pointers", "invalid count")
    keys: set[str] = set()
    for pointer in pointers:
        parts = _read_pointer(pointer, path, key, python=False)
        if len(parts) != 3 or parts[:2] != ("model", "vocab"):
            raise _config_error(path, key, "a /model/vocab/<key> pointer", "invalid value")
        _unique(keys, parts[2], path, key, "distinct vocabulary keys", "duplicate", _config_error)
    return frozenset(keys)


def _public_vocab_spec(row: Any, path: Path, where: str) -> public_vocab.PublishedVocabulary:
    if not isinstance(row, dict):
        raise _config_error(path, where, "a table", type(row).__name__)
    name = _string(row, "path", path, f"{where}.path")
    _validate_exact_path(path, f"{where}.path", name)
    if not name.endswith((".json", ".json.gz")):
        raise _config_error(path, where, "a .json or .json.gz path", "invalid suffix")
    archive = name.endswith(".json.gz")
    _check_keys(row, (*_PUBLIC_VOCABULARY_FIELDS, *(_PUBLIC_ARCHIVE_FIELDS if archive else ())), path, where)
    url, revision = _published_release(row, path, where)
    size = _integer(
        row, "published_size", path, f"{where}.published_size", minimum=1,
        maximum=public_vocab.MAX_PUBLISHED_BYTES,
    )
    sha256 = _provenance_digest(row, "published_sha256", path, where)
    keys = _published_keys(row, path, where)
    if not archive:
        return public_vocab.PublishedVocabulary(name, url, revision, sha256, size, keys)
    compressed = _provenance_digest(row, "compressed_sha256", path, where)
    compressed_size = _integer(
        row, "compressed_size", path, f"{where}.compressed_size", minimum=1,
        maximum=secrets.MAX_PUBLIC_VOCABULARY_GZIP_BYTES,
    )
    return public_vocab.PublishedVocabulary(
        name, url, revision, sha256, size, keys, compressed, compressed_size,
    )


def _public_vocabulary(
    raw: dict[str, Any], path: Path, key: str,
) -> tuple[public_vocab.PublishedVocabulary, ...]:
    name = f"{key}.public_vocabulary"
    rows = raw.get("public_vocabulary", [])
    if not isinstance(rows, list) or len(rows) > public_vocab.MAX_ASSETS:
        raise _config_error(path, name, f"up to {public_vocab.MAX_ASSETS} tables", "invalid value")
    declarations = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        where = f"{name}[{index}]"
        declaration = _public_vocab_spec(row, path, where)
        _unique(seen, declaration.path, path, where, "a unique asset path", "duplicate", _config_error)
        declarations.append(declaration)
    return tuple(declarations)


def _byte_span(
    row: dict[str, Any], prefix: str, path: Path, where: str, limit: int,
) -> tuple[int, int]:
    start_key, end_key = f"{prefix}_start", f"{prefix}_end"
    start = _integer(row, start_key, path, f"{where}.{start_key}", minimum=0, maximum=limit)
    end = _integer(row, end_key, path, f"{where}.{end_key}", minimum=1, maximum=limit)
    if end <= start:
        raise _config_error(path, where, "an increasing half-open byte interval", "invalid span")
    return start, end


def _model_catalogue(
    row: dict[str, Any], path: Path, where: str, record: str,
) -> public_hardware_model.Catalogue:
    name = f"{where}.catalogue"
    catalogue = _read_value(row, "catalogue", path, name, _TABLE)
    _check_keys(catalogue, _MODEL_CATALOGUE_FIELDS, path, name)
    payload = _read_value(catalogue, "payload", path, f"{name}.payload", _TABLE)
    source = _git_payload(payload, path, f"{name}.payload")
    digest = _provenance_digest(catalogue, "sha256", path, name)
    literal_span = _byte_span(catalogue, "literal", path, name, source.size)
    if record == source.path:
        raise _config_error(path, where, "a separate catalogue operand", "identical paths")
    return public_hardware_model.Catalogue(source, digest, literal_span)


def _python_model_spec(
    row: dict[str, Any], path: Path, where: str, record: str,
) -> public_hardware_model.PythonDeclaration:
    _check_keys(row, _PYTHON_MODEL_FIELDS, path, where)
    role = _string(row, "role", path, f"{where}.role")
    if role not in ("keyword", "attribute_equality"):
        raise _config_error(path, f"{where}.role", "keyword or attribute_equality", "invalid role")
    identifier = _string(row, "identifier", path, f"{where}.identifier")
    if not identifier.isascii() or not identifier.isidentifier() or keyword.iskeyword(identifier):
        raise _config_error(path, f"{where}.identifier", "an ASCII Python identifier", "invalid identifier")
    span = _byte_span(row, "match", path, where, secrets._MAX_RECORD_BYTES)
    digest = _provenance_digest(row, "source_sha256", path, where)
    catalogue = _model_catalogue(row, path, where, record)
    if digest == catalogue.sha256:
        raise _config_error(path, where, "distinct source and catalogue bytes", "identical digests")
    return public_hardware_model.PythonDeclaration(record, role, identifier, span, digest, catalogue)


def _public_model_spec(row: Any, path: Path, where: str) -> public_hardware_model.ModelDeclaration:
    _read_scalar(path, where, row, _TABLE)
    record = _string(row, "record", path, f"{where}.record")
    _validate_exact_path(path, f"{where}.record", record)
    if record.endswith(".py"):
        return _python_model_spec(row, path, where, record)
    if not record.endswith((".json", ".json.gz")):
        raise _config_error(path, where, "a .json, .json.gz or .py record path", "invalid suffix")
    archive = record.endswith(".json.gz")
    allowed = (*_PUBLIC_MODEL_FIELDS, "compressed_sha256") if archive else _PUBLIC_MODEL_FIELDS
    _check_keys(row, allowed, path, where)
    pointer_text = _string(row, "pointer", path, f"{where}.pointer")
    pointer = _read_pointer(pointer_text, path, f"{where}.pointer", python=False)
    span = _byte_span(row, "match", path, where, secrets._MAX_RECORD_BYTES)
    catalogue = _model_catalogue(row, path, where, record)
    decoded = _provenance_digest(row, "decoded_sha256", path, where)
    compressed = _provenance_digest(row, "compressed_sha256", path, where) if archive else None
    return public_hardware_model.Declaration(record, pointer, span, decoded, catalogue, compressed)


def _public_models(
    raw: dict[str, Any], path: Path, key: str,
) -> tuple[public_hardware_model.ModelDeclaration, ...]:
    name = f"{key}.{_PUBLIC_MODEL_KEY}"
    rows = raw.get(_PUBLIC_MODEL_KEY, [])
    if not isinstance(rows, list):
        raise _config_error(path, name, "an array of tables", "invalid value")
    declarations = []
    pointers: set[tuple[str, tuple[str, ...]]] = set()
    matches: set[tuple[str, tuple[int, int]]] = set()
    for index, row in enumerate(rows):
        where = f"{name}[{index}]"
        declaration = _public_model_spec(row, path, where)
        if isinstance(declaration, public_hardware_model.Declaration):
            _unique(pointers, (declaration.record, declaration.pointer), path, where,
                    "a unique record and pointer", "duplicate", _config_error)
        _unique(matches, (declaration.record, declaration.match_span), path, where,
                "a unique record and match interval", "duplicate", _config_error)
        declarations.append(declaration)
    return tuple(declarations)


@dataclass(frozen=True)
class _SecretsSpec:
    digests: tuple[secrets.Provenance, ...]
    vocabulary: tuple[public_vocab.PublishedVocabulary, ...]
    models: tuple[public_hardware_model.ModelDeclaration, ...]


def _secrets_spec(raw: dict[str, Any], _root: Path, path: Path, key: str) -> ParsedSpec:
    return ParsedSpec(
        _SecretsSpec(_secrets_provenance(raw, path, key), _public_vocabulary(raw, path, key),
                     _public_models(raw, path, key)),
        "secrets/1", ("static",),
    )


def _secrets_result(context: AdapterContext, start: float, child: RunResult, budget: int) -> Any:
    from .checks import _check_result

    passed = child.execution == "completed" and child.returncode == 0
    reason = None if passed else child.error or f"Betterleaks exited {child.returncode}"
    return _check_result(
        context.check, start, "pass" if passed else "fail", execution=child.execution,
        reason=reason, diagnostics=child.diagnostics(), budget_seconds=budget,
    )


def _scanner_measurement(scan: secrets.VerifiedScan, spec: _SecretsSpec) -> dict[str, Any]:
    measurement: dict[str, Any] = {"verified_sha256_provenance": scan.verified}
    if spec.vocabulary:
        fields = ("path", "rule", "start_line", "end_line", "start_column", "end_column")
        measurement["verified_public_vocabulary"] = len(scan.vocabulary)
        measurement["public_vocabulary_locations"] = [
            [dict(zip(fields, coordinate, strict=True)) for coordinate in row] for row in scan.vocabulary
        ]
    if spec.models:
        measurement["verified_public_hardware_models"] = scan.public_models
    return measurement


def _verified_secrets_result(
    context: AdapterContext, start: float, scan: secrets.VerifiedScan, budget: int, spec: _SecretsSpec,
) -> Any:
    from .checks import _check_result

    child = scan.child
    reason = child.error
    if child.execution == "completed" and scan.unresolved:
        reason = f"Betterleaks reported {scan.unresolved} unresolved finding(s)"
    return _check_result(
        context.check, start,
        "pass" if child.execution == "completed" and scan.unresolved == 0 else "fail",
        execution=child.execution, reason=reason, diagnostics=child.diagnostics(),
        budget_seconds=budget, measurement=_scanner_measurement(scan, spec),
    )


def _secrets_paths(root: Path) -> tuple[list[str], set[str]]:
    entries = enumerate_entries(root)
    selected = [entry.path for entry in entries if not entry.gitlink]
    tracked = {entry.path for entry in entries if entry.mode in ("100644", "100755")}
    return selected, tracked


def _secrets_git_command(
    root: Path, budget: float, *args: str, env: dict[str, str], capture_limit: int,
) -> RunResult | None:
    remaining = remaining_budget(budget)
    if remaining <= 0:
        return None
    return run(
        git_argv(root, "-c", "advice.graftFileDeprecated=false", *args),
        env=env, budget_seconds=remaining, capture_limit=capture_limit,
    )


def _trusted_proof_spec(context: AdapterContext) -> _SecretsSpec:
    spec = context.check.spec
    if context.config.policy_from_trusted_directory:
        return spec
    return _SecretsSpec(spec.digests, (), ())


def _scan_secrets(context: AdapterContext, binary: Path, directory: Path, start: float, budget: int) -> Any:
    root = context.root.resolve()
    selected, tracked = _secrets_paths(root)
    spec = _trusted_proof_spec(context)
    if context.config.trusted_policy and (spec.digests or spec.vocabulary or spec.models):
        prepare = partial(public_hardware_model.prepare_scan, spec.models) if spec.models else None
        verified = secrets.scan_verified(
            binary, root, directory, selected, budget, spec.digests,
            tracked=tracked, open_parent=_parent_fd, run=run,
            git_run=partial(_secrets_git_command, root, budget), public_vocabulary=spec.vocabulary,
            prepare_models=prepare,
        )
        return _verified_secrets_result(context, start, verified, budget, spec)
    child = secrets.scan(binary, root, directory, selected, budget, open_parent=_parent_fd, run=run)
    return _secrets_result(context, start, child, budget)


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
            return _scan_secrets(context, binary, Path(directory), start, RATCHET_BUDGET_SECONDS)
    except (GateError, OSError, ValueError) as error:
        print(f"{context.prefix}: {error}", file=sys.stderr)
        return _check_result(
            context.check, start, "error", execution="error", reason=str(error),
            diagnostics=Diagnostics(error=str(error)),
        )


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
    if report["error"] is not None:
        return "fail", report["error"]
    if returncode:
        return "fail", f"command exited {returncode}"
    if not report["finished"]:
        return "fail", "unittest did not finish validating the discovery occurrences"
    if report["omitted"]:
        return "not_run", report["selection"]["reason"]
    if not report["executed"]:
        return "fail", "no test executed"
    return "pass", None


def _occurrence_labels(ids: list[str | None]) -> dict[int, str]:
    counts = Counter(ids)
    reserved = set(counts)
    labels = {}
    for position, name in enumerate(ids):
        if name is None:
            continue
        label = name
        if counts[name] > 1:
            label = f"{name} (discovery occurrence {len(labels) + 1})"
            while label in reserved:
                label += " (duplicate)"
            reserved.add(label)
        labels[position] = label
    return labels


def _affected_selection_report(labels: dict[int, str], full: str | None) -> dict:
    if full is None:
        return {
            "selected": {},
            "left_out": dict.fromkeys(labels.values(), "no changed file affects this test"),
            "reason": "no affected tests discovered",
        }
    return {"selected": dict.fromkeys(labels.values(), full), "left_out": {}, "reason": full}


def _affected_invocations(labels: dict[int, str], events: dict[str, list]) -> dict:
    outcomes = {position: outcome for position, _, outcome, _ in events["terminal"]}
    started = set(events["started"])
    executed, skipped, outstanding = [], [], {}
    for position, label in labels.items():
        outcome = outcomes.get(position)
        if outcome in (None, "blocked"):
            outstanding[label] = _outstanding_reason(outcome, position in started)
        elif outcome in ("skipped", "fixture skipped"):
            skipped.append(label)
        else:
            executed.append(label)
    return {"executed": executed, "skipped": skipped, "not_executed": outstanding}


def _outstanding_reason(outcome: str | None, started: bool) -> str:
    if outcome == "blocked":
        return "fixture setup failed"
    if started:
        return "invocation interrupted"
    return "the run did not invoke this selected test"


def _affected_failures(labels: dict[int, str], events: dict[str, list]) -> list[str]:
    failed = {"failure", "error", "unexpected success"}
    return [
        labels[pos] for pos, _, outcome, _ in events["terminal"] if pos in labels and outcome in failed
    ] + [name for name, outcome, _ in events["fixture"] if outcome in failed]


def _read_affected_report(path: Path) -> dict:
    with path.open(encoding="utf-8") as journal:
        header = load_json(journal.readline())
        events = {name: [] for name in ("started", "terminal", "fixture", "error", "finished")}
        for line in journal:
            if line.endswith("\n"):
                event, value = load_json(line)
                events[event].append(value)
    return _affected_journal_report(header, events)


def _affected_journal_report(header: dict, events: dict[str, list]) -> dict:
    labels = _occurrence_labels(header["ids"])
    full, errors = header["full"], header["discovery_errors"]
    error = errors[0].splitlines()[0] if errors else next(iter(events["error"]), None)
    return {
        "selection": _affected_selection_report(labels, full),
        "discovery_errors": errors,
        "omitted": full is None,
        "finished": bool(events["finished"]),
        "error": error,
        "failed": _affected_failures(labels, events),
        **_affected_invocations(labels if full is not None else {}, events),
    }


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
    report.pop("finished")
    report.pop("error")
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
        "argv": argv, "full": selection.full_suite,
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
    name = descriptor.name
    label = f"adapter {name!r}"
    if name in ADAPTERS:
        raise ValueError(f"{label}: duplicate name")
    mode = descriptor.file_selection
    if mode is not None and (not isinstance(mode, str) or mode not in ("expanded", "affected")):
        raise ValueError(f"{label}: file_selection must be 'expanded', 'affected', or None")
    _validate_adapter_keys(descriptor.keys, label)
    if not callable(descriptor.budget):
        raise ValueError(f"{label}: budget must be callable")
    ADAPTERS[name] = descriptor
    return descriptor


def _validate_adapter_keys(keys: tuple[str, ...], label: str) -> None:
    if not isinstance(keys, tuple):
        raise ValueError(f"{label}: keys must be a tuple")
    seen = set(COMMON_CHECK_KEYS)
    try:
        for index, key in enumerate(keys):
            field = f"keys[{index}]"
            _read_scalar(label, field, key, _STRING)
            _unique(
                seen, key, label, field, "a distinct adapter key", f"duplicate or reserved key {key!r}",
                _config_error,
            )
    except ConfigError as error:
        raise ValueError(str(error)) from error


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
    file_selection="expanded",
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
    elisp_lint.LINT_KEYS,
    elisp_lint._elisp_lint_spec,
    partial(elisp_lint.run_lint, mode="compile"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
    file_selection="affected",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "elisp_checkdoc",
    elisp_lint.LINT_KEYS,
    elisp_lint._elisp_lint_spec,
    partial(elisp_lint.run_lint, mode="checkdoc"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
    file_selection="affected",
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
    file_selection="expanded",
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
    ("scope", "base", "mutant_seconds", "function_mutants", "run_seconds", "test_runner"),
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
    file_selection="expanded",
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
    file_selection="expanded",
    runs_suite=False,
))
register_adapter(AdapterDescriptor(
    "secrets",
    ("sha256_provenance", "public_vocabulary", _PUBLIC_MODEL_KEY),
    _secrets_spec,
    _run_secrets,
    runs_suite=False,
))
