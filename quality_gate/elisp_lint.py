"""Run isolated Emacs Lisp compilation and checkdoc checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .elisp_tests import _common_spec, _lisp_string, _temporary, _validate_report_version, probe_version
from .json_input import load_json
from .runner import analysis_step, mark_step, record_diagnostics, remaining_budget, run


if TYPE_CHECKING:
    from .adapters import ParsedSpec


@dataclass(frozen=True)
class ElispLintSpec:
    load_path: tuple[str, ...]
    emacs: str
    budget_seconds: int


def _elisp_lint_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    return ParsedSpec(parse_spec(raw, root, path, full_key), "elisp-lint/1", ("static",))


def parse_spec(raw: dict[str, Any], root: Path, path: Path, key: str) -> ElispLintSpec:
    """Parse and validate the shared compile and checkdoc configuration."""
    return ElispLintSpec(*_common_spec(raw, root, path, key))


def _command(spec: ElispLintSpec, mode: str, files: list[str], output: Path, report: Path) -> list[str]:
    directories = [item for directory in spec.load_path for item in ("-L", directory)]
    names = " ".join(_lisp_string(name) for name in files)
    extra = _lisp_string(str(output)) + " " if mode == "elisp_compile" else ""
    form = f"(qg-elisp-lint-{mode.removeprefix('elisp_')} '({names}) {extra}{_lisp_string(str(report))})"
    helper = Path(__file__).with_name("elisp") / "qg-elisp-lint.el"
    return [spec.emacs, "-Q", "--batch", *directories, "-l", str(helper), "--eval", form]


def _issue_location(issue: dict[str, Any], files: list[str]) -> bool:
    line = issue["line"]
    return issue["file"] in files and isinstance(line, int) and not isinstance(line, bool) and line > 0


def _issue_valid(issue: Any, files: list[str]) -> bool:
    if not isinstance(issue, dict) or set(issue) != {"file", "line", "message"}:
        return False
    return _issue_location(issue, files) and isinstance(issue["message"], str) and bool(issue["message"])


def _document_header(document: Any, files: list[str]) -> bool:
    if not isinstance(document, dict) or set(document) != {"emacs_version", "files", "failed", "issues"}:
        return False
    return document["files"] == files


def _document_valid(document: Any, files: list[str], mode: str) -> bool:
    if not _document_header(document, files):
        return False
    if not isinstance(document["failed"], list) or not isinstance(document["issues"], list):
        return False
    return _content_valid(document, files, mode)


def _failed_valid(failed: list[Any], files: list[str]) -> bool:
    return all(isinstance(name, str) and name in files for name in failed)


def _content_valid(document: dict[str, Any], files: list[str], mode: str) -> bool:
    failed, issues = document["failed"], document["issues"]
    return (_failed_valid(failed, files) and all(_issue_valid(issue, files) for issue in issues)
            and not (issues if mode == "elisp_compile" else failed))


def _read_document(path: Path, files: list[str], mode: str, version: str) -> dict[str, Any]:
    try:
        document = load_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"a JSON lint report, got {error}") from error
    _validate_report_version(document, version)
    if not _document_valid(document, files, mode):
        raise ValueError(f"a valid {mode} report for {files!r}, got {document!r}")
    return document


def _compile_failed(document: dict[str, Any]) -> bool:
    return len(document["failed"]) > 0


def _checkdoc_failed(document: dict[str, Any]) -> bool:
    return len(document["issues"]) > 0


def _compile_problem(document: dict[str, Any], child: Any) -> str | None:
    if _compile_failed(document):
        messages = child.combined_text.strip() or "byte compiler did not complete successfully"
        names = ", ".join(document["failed"] or document["files"])
        return f"{names}: {messages}"
    return None


def _checkdoc_problem(document: dict[str, Any]) -> str | None:
    if _checkdoc_failed(document):
        return "\n".join(f"{item['file']}:{item['line']}: {item['message']}" for item in document["issues"])
    return None


def _problem(mode: str, document: dict[str, Any], child: Any) -> str | None:
    if mode == "elisp_compile":
        return _compile_problem(document, child)
    return _checkdoc_problem(document)


def _failure(context: Any, start: float, reason: str, *, version: str | None = None,
             outcome: str = "fail", execution: str = "completed", diagnostics: Any = None) -> Any:
    from .checks import _tests_result

    if version is not None:
        reason += f" (Emacs {version})"
    return _tests_result(context.check, context.check.spec, start, context.prefix, reason,
                         outcome=outcome, execution=execution, diagnostics=diagnostics,
                         tool={"name": "Emacs", "version": version} if version is not None else None)


def _execution_failure(context: Any, start: float, child: Any, version: str | None) -> Any:
    if child.execution == "budget":
        return _failure(context, start, "Emacs exceeded its budget", version=version, execution="budget",
                        diagnostics=child.diagnostics())
    if child.execution == "error":
        reason = f"expected Emacs command {context.check.spec.emacs!r}, got {child.error}"
        return _failure(context, start, reason, version=version, outcome="unsupported", execution="error",
                        diagnostics=child.diagnostics())
    return None


def _run_batch(context: Any, start: float, files: list[str], directory: Path,
               version: str) -> tuple[Any, Any, Any]:
    spec, mode = context.check.spec, context.check.adapter
    report = directory / "result.json"
    report.unlink(missing_ok=True)
    mark_step("Emacs lint command")
    child = run(_command(spec, mode, files, directory, report), cwd=context.root,
                budget_seconds=remaining_budget(spec.budget_seconds))
    record_diagnostics(child.diagnostics())
    failure = _execution_failure(context, start, child, version)
    if failure is not None:
        return None, child, failure
    try:
        document = analysis_step("Emacs lint report validation", _read_document, report, files, mode, version)
    except ValueError as error:
        reason = f"expected {error} for {files!r}; child exit {child.returncode}, execution {child.execution}"
        return None, child, _failure(context, start, reason, version=version, outcome="unsupported",
                                     execution=child.execution, diagnostics=child.diagnostics())
    if child.returncode != 0:
        reason = f"expected child exit 0 with a lint report, got exit {child.returncode}"
        return None, child, _failure(context, start, reason, version=version,
                                     outcome="unsupported", execution=child.execution,
                                     diagnostics=child.diagnostics())
    return document, child, None


def _batches(mode: str, files: list[str]) -> list[list[str]]:
    return [[name] for name in files] if mode == "elisp_compile" else [files]


def _finish(context: Any, start: float, version: str, problems: list[str], diagnostics: Any) -> Any:
    from .checks import _check_result

    if problems:
        return _failure(context, start, "\n".join(problems), version=version, diagnostics=diagnostics)
    result = _check_result(context.check, start, "pass", budget_seconds=context.check.spec.budget_seconds,
                           diagnostics=diagnostics, tool={"name": "Emacs", "version": version})
    print(f"{context.prefix}: passed (Emacs {version}, {result.duration_seconds:.2f}s)", flush=True)
    return result


@dataclass
class _State:
    version: str
    problems: list[str] = field(default_factory=list)
    diagnostics: Any = None


def _record_problem(context: Any, state: _State, document: dict[str, Any], child: Any) -> None:
    problem = analysis_step("Emacs lint findings", _problem, context.check.adapter, document, child)
    if problem is not None:
        state.problems.append(problem)
        state.diagnostics = child.diagnostics()
    elif state.diagnostics is None:
        state.diagnostics = child.diagnostics()


def _collect_batch(context: Any, start: float, batch: list[str], directory: Path, state: _State) -> Any:
    document, child, failure = _run_batch(context, start, batch, directory, state.version)
    if failure is not None:
        return failure
    _record_problem(context, state, document, child)
    return None


def run_lint(context: Any) -> Any:
    """Run each selected source through the configured lint check."""
    from .checks import _adapter_selection, _class_text

    version, failure = probe_version(context)
    if failure is not None:
        return failure
    _spec, start, selected, names = _adapter_selection(context)
    if not selected:
        reason = f"no files selected (classes: {_class_text(names)}); zero inputs is not a pass"
        return _failure(context, start, reason)
    state = _State(version)
    with _temporary() as temporary:
        for batch in _batches(context.check.adapter, selected):
            failure = _collect_batch(context, start, batch, Path(temporary), state)
            if failure is not None:
                return failure
    return _finish(context, start, state.version, state.problems, state.diagnostics)
