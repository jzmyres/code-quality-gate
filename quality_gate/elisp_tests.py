"""Run an ERT suite once and collect Edebug definition coverage."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import reuse
from .policy import (
    DEFAULT_TESTS_BUDGET_SECONDS,
    _config_error,
    _integer,
    _optional_string_list,
    _string,
)
from .runner import analysis_step, mark_step, record_diagnostics, remaining_budget, run
from .tracing import current as current_recorder


@dataclass(frozen=True)
class ElispTestsSpec:
    suite: str
    load_path: tuple[str, ...]
    emacs: str
    budget_seconds: int


def _resolved_path(root: Path, target: Path, path: Path, key: str, kind: str) -> Path:
    try:
        return (root / target).resolve()
    except (OSError, RuntimeError) as error:
        raise _config_error(path, key, f"a repository-relative {kind}", str(error)) from error


def _safe_relative(value: str, target: Path) -> bool:
    return bool(value.strip()) and "\0" not in value and not target.is_absolute() and ".." not in target.parts


def _relative_path(root: Path, value: str, path: Path, key: str, kind: str) -> None:
    target = Path(value)
    if not _safe_relative(value, target):
        raise _config_error(path, key, f"a repository-relative {kind}", repr(value))
    resolved = _resolved_path(root, target, path, key, kind)
    if not resolved.is_relative_to(root.resolve()):
        raise _config_error(path, key, f"a repository-relative {kind}", repr(value))
    exists = resolved.is_file() if kind == "regular file" else resolved.is_dir()
    if not exists:
        raise _config_error(path, key, f"a {kind}", f"{value!r} is missing or not a {kind}")


def parse_spec(raw: dict[str, Any], root: Path, path: Path, key: str) -> ElispTestsSpec:
    suite = _string(raw, "suite", path, f"{key}.suite")
    _relative_path(root, suite, path, f"{key}.suite", "regular file")
    load_path = _optional_string_list(raw, "load_path", path, f"{key}.load_path")
    for index, directory in enumerate(load_path):
        _relative_path(root, directory, path, f"{key}.load_path[{index}]", "directory")
    emacs = _string(raw, "emacs", path, f"{key}.emacs") if "emacs" in raw else "emacs"
    if "\0" in emacs:
        raise _config_error(path, f"{key}.emacs", "a command without NUL", repr(emacs))
    budget = _integer(raw, "budget_seconds", path, f"{key}.budget_seconds",
                      default=DEFAULT_TESTS_BUDGET_SECONDS, minimum=1)
    return ElispTestsSpec(suite, load_path, emacs, budget)


def _lisp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _command(spec: ElispTestsSpec, root: Path, files: list[str], stage: Path, result: Path) -> list[str]:
    directories = [item for directory in spec.load_path for item in ("-L", directory)]
    paths = " ".join(_lisp_string(name) for name in files)
    form = (f"(qg-elisp-stage-run {_lisp_string(str(root) + os.sep)} '({paths}) "
            f"{_lisp_string(spec.suite)} {_lisp_string(str(result))})")
    return [spec.emacs, "-Q", "--batch", *directories, "-l", str(stage), "--eval", form]


def _stage(directory: Path) -> Path:
    source = Path(__file__).with_name("elisp") / "qg-elisp-child.el"
    stage = directory / "stage.el"
    stage.write_text(source.read_text(encoding="utf-8").replace("qg-elisp-child", "qg-elisp-stage"),
                     encoding="utf-8")
    return stage


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _definition_shape(item: Any) -> bool:
    return isinstance(item, dict) and set(item) == {"symbol", "file", "position", "stop_points", "reached"}


def _definition_names(item: dict[str, Any]) -> bool:
    return all(isinstance(item[key], str) and item[key] for key in ("symbol", "file"))


def _definition_file(item: dict[str, Any], selected: list[str] | None) -> bool:
    filename = Path(item["file"])
    if filename.is_absolute() or ".." in filename.parts:
        return False
    return selected is None or item["file"] in selected


def _definition_counts(item: dict[str, Any]) -> bool:
    return (all(_count(item[key]) for key in ("position", "stop_points", "reached"))
            and item["position"] > 0 and item["reached"] <= item["stop_points"])


def _definition(item: Any, selected: list[str] | None) -> bool:
    return (_definition_shape(item) and _definition_names(item)
            and _definition_file(item, selected) and _definition_counts(item))


def _failure(item: Any) -> bool:
    return (isinstance(item, dict) and set(item) == {"name", "condition"}
            and all(isinstance(item[key], str) and item[key] for key in ("name", "condition")))


def _validate_shape(document: Any) -> None:
    if not isinstance(document, dict):
        raise ValueError("a JSON object")
    keys = {"emacs_version", "selected", "passed", "failed", "skipped", "failures", "definitions"}
    if set(document) != keys:
        raise ValueError(f"keys {sorted(keys)}, got {sorted(document)}")


def _validate_counts(document: dict[str, Any]) -> None:
    if not isinstance(document["emacs_version"], str) or not document["emacs_version"]:
        raise ValueError("a non-empty emacs_version")
    if not all(_count(document[key]) for key in ("selected", "passed", "failed", "skipped")):
        raise ValueError("non-negative integer test counts")
    if document["selected"] != document["passed"] + document["failed"] + document["skipped"]:
        raise ValueError("selected equal to passed + failed + skipped")


def _validate_failures(document: dict[str, Any]) -> None:
    failures = document["failures"]
    if not isinstance(failures, list) or not all(_failure(item) for item in failures):
        raise ValueError("a list of named failure conditions")
    if len(failures) != document["failed"]:
        raise ValueError("one condition per unexpected result")


def _validate_definitions(document: dict[str, Any], selected: list[str] | None) -> None:
    definitions = document["definitions"]
    if not isinstance(definitions, list) or not all(_definition(item, selected) for item in definitions):
        raise ValueError("a list of valid instrumented definitions")


def validate_document(document: Any, selected: list[str] | None = None) -> dict[str, Any]:
    """Validate a child measurement, raising ValueError on malformed evidence."""
    _validate_shape(document)
    _validate_counts(document)
    _validate_failures(document)
    _validate_definitions(document, selected)
    return document


def _error_document(document: Any) -> bool:
    if not isinstance(document, dict) or set(document) != {"error"}:
        return False
    error = document["error"]
    return isinstance(error, str) and bool(error)


def _read_document(path: Path, selected: list[str]) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"a JSON result document, got {error}") from error
    if _error_document(document):
        return document
    try:
        validated = validate_document(document, selected)
        path.write_bytes(reuse._canonical(validated))
        return validated
    except (OSError, ValueError) as error:
        raise ValueError(f"a valid result ({error}), got {document!r}") from error


def apply_document(result: Any, document: dict[str, Any]) -> None:
    """Attach normalized results and definition evidence to a check result."""
    from .checks import TestResults

    failures = tuple(f"{item['name']}: {item['condition']}" for item in document["failures"])
    result.test_results = TestResults(document["selected"], document["passed"], document["failed"], failures)
    result.tests_ran = document["selected"]
    result.tests_skipped = document["skipped"]
    result.measurement = {"tests": document["selected"] - document["skipped"]}
    result.emacs_version = document["emacs_version"]
    result.definitions = document["definitions"]


def _verdict(document: dict[str, Any]) -> str | None:
    if document["selected"] == document["skipped"]:
        return f"no test executed: {document['selected']} selected, {document['skipped']} skipped"
    if document["failed"]:
        return "unexpected test results: " + "; ".join(
            f"{item['name']}: {item['condition']}" for item in document["failures"]
        )
    return None


def validate_reused_document(document: Any) -> dict[str, Any]:
    """Stored evidence must describe a passing, executed ERT run."""
    result = validate_document(document)
    problem = _verdict(result)
    if problem is not None:
        raise ValueError(problem)
    return result


def _temporary() -> tempfile.TemporaryDirectory[str]:
    temporary = tempfile.TemporaryDirectory(prefix="qg-elisp-")
    recorder = current_recorder()
    if recorder is not None:
        recorder.temporary_paths.add(temporary.name)
    session = reuse.current()
    if session is not None:
        session.temporary_paths.add(temporary.name)
    return temporary


def _finish(context: Any, start: float, run_result: Any, document: dict[str, Any],
            temporary: Any, evidence: Path) -> Any:
    from .checks import _check_result, _tests_result

    check, prefix, spec = context.check, context.prefix, context.check.spec
    diagnostics = run_result.diagnostics()
    if "error" in document:
        return _tests_result(check, spec, start, prefix, document["error"], diagnostics=diagnostics)
    if run_result.returncode != 0:
        reason = f"expected child exit 0 with a result, got exit {run_result.returncode}"
        return _tests_result(check, spec, start, prefix, reason, outcome="unsupported",
                             diagnostics=diagnostics)
    reason = _verdict(document)
    result = _check_result(check, start, "fail" if reason else "pass", budget_seconds=spec.budget_seconds,
                           diagnostics=diagnostics, reason=reason, evidence_path=evidence,
                           temporary=temporary)
    apply_document(result, document)
    if reason:
        print(f"{prefix}: {reason} (Emacs {result.emacs_version})", file=sys.stderr)
    else:
        print(f"{prefix}: passed ({result.measurement['tests']} tests, Emacs {result.emacs_version}, "
              f"{result.duration_seconds:.2f}s)", flush=True)
    return result


def _execution_failure(context: Any, start: float, run_result: Any) -> Any:
    from .checks import _tests_result

    check, prefix, spec = context.check, context.prefix, context.check.spec
    if run_result.execution == "budget":
        return _tests_result(check, spec, start, prefix, "Emacs exceeded its budget", execution="budget",
                             diagnostics=run_result.diagnostics())
    if run_result.execution == "error":
        reason = f"expected Emacs command {spec.emacs!r}, got {run_result.error}"
        return _tests_result(check, spec, start, prefix, reason, outcome="unsupported", execution="error",
                             diagnostics=run_result.diagnostics())
    return None


def _same_file(first: Path, second: Path) -> bool:
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _suite_collision(context: Any, selected: list[str], start: float) -> Any:
    from .checks import _tests_result

    spec = context.check.spec
    suite = context.root / spec.suite
    for name in selected:
        if _same_file(context.root / name, suite):
            reason = f"check {context.check.id}: suite {spec.suite} is also instrumented as {name}"
            return _tests_result(context.check, spec, start, context.prefix, reason, outcome="error",
                                 configuration_error=True)
    return None


def run_tests(context: Any) -> Any:
    """Run the configured suite and return its check result and reusable evidence."""
    from .checks import _select_files, _tests_result

    start = time.monotonic()
    spec = context.check.spec
    selected, _classes = _select_files(context.config, context.check, context.files, context.classes)
    collision = _suite_collision(context, selected, start)
    if collision is not None:
        return collision
    temporary = _temporary()
    directory = Path(temporary.name)
    stage = _stage(directory)
    evidence = directory / "result.json"
    mark_step("Emacs test command")
    child = run(_command(spec, context.root, selected, stage, evidence), cwd=context.root,
                budget_seconds=remaining_budget(spec.budget_seconds))
    record_diagnostics(child.diagnostics())
    failure = _execution_failure(context, start, child)
    if failure is not None:
        return failure
    try:
        document = analysis_step("Emacs result validation", _read_document, evidence, selected)
    except ValueError as error:
        reason = f"expected {error}; child exit {child.returncode}, execution {child.execution}"
        return _tests_result(context.check, spec, start, context.prefix, reason, outcome="unsupported",
                             execution=child.execution, diagnostics=child.diagnostics())
    return _finish(context, start, child, document, temporary, evidence)
