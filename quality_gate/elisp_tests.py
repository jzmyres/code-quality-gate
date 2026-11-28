"""Run an ERT suite once and collect Edebug definition coverage."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .json_input import load_json
from .policy import (
    DEFAULT_TESTS_BUDGET_SECONDS,
    _config_error,
    _integer,
    _optional_string_list,
    _string,
)
from .ratchet import FindingResult
from .runner import execution_outcome, mark_step, run


if TYPE_CHECKING:
    from .adapters import ParsedSpec


ELISP_MINIMUM_VERSION = "30.1"
_VERSION_TEXT_LIMIT = 128
ERT_OUTCOMES = {
    "ert-test-passed": "completed",
    "ert-test-failed": "completed",
    "ert-test-skipped": "skipped",
    "ert-test-quit": None,
    "ert-test-aborted-with-non-local-exit": None,
}


@dataclass(frozen=True)
class ElispTestsSpec:
    suite: str
    load_path: tuple[str, ...]
    emacs: str
    budget_seconds: int


def _elisp_tests_spec(
    raw: dict[str, Any], root: Path | None, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    return ParsedSpec(parse_spec(raw, root, path, full_key), "test-count/1", ("tests",))


def _numeric_version(version: str) -> bool:
    """Bound total parsing work and each integer conversion independently of Python's limit."""
    return (len(version) <= _VERSION_TEXT_LIMIT
            and re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,9})+", version) is not None)


def _version_excerpt(version: str) -> str:
    return version[:_VERSION_TEXT_LIMIT] + ("..." if len(version) > _VERSION_TEXT_LIMIT else "")


def _version_probe_reason(child: Any, emacs: str) -> str | None:
    if child.execution != "completed" or child.returncode != 0:
        shown = _version_excerpt(child.error or child.combined_text)
        return (f"expected Emacs command {emacs!r} to report its version, got "
                f"exit {child.returncode}, execution {child.execution}: {shown}")
    if child.output_truncated or len(child.combined_text) > _VERSION_TEXT_LIMIT:
        shown = _version_excerpt(child.combined_text)
        return (f"expected complete Emacs version output of at most {_VERSION_TEXT_LIMIT} characters "
                f"from command {emacs!r}, got {shown!r}")
    return None


def _version_reason(child: Any, emacs: str, minimum: str) -> str | None:
    failure = _version_probe_reason(child, emacs)
    if failure is not None:
        return failure
    version = child.combined_text.strip()
    if not _numeric_version(version):
        shown = _version_excerpt(version)
        return (f"expected a numeric Emacs version from command {emacs!r}, got {shown!r}; "
                f"minimum required is {minimum}")
    if tuple(map(int, version.split("."))) < tuple(map(int, minimum.split("."))):
        return f"found Emacs {version}; minimum required is Emacs {minimum}"
    return None


def probe_version(context: Any) -> tuple[str | None, Any]:
    """Return the accepted Emacs version or a preflight failure before loading measured code."""
    from .adapters import adapter_for
    from .checks import _check_result

    start = time.monotonic()
    spec = context.check.spec
    if not hasattr(spec, "emacs"):
        spec = context.config.checks[spec.requires].spec
    budget = adapter_for(context.check.adapter).budget(context.check.spec)
    mark_step("Emacs version check")
    child = run([spec.emacs, "-Q", "--batch", "--eval", "(princ emacs-version)"],
                cwd=context.root, budget_seconds=budget)
    reason = _version_reason(child, spec.emacs, ELISP_MINIMUM_VERSION)
    if reason is None:
        return child.combined_text.strip(), None
    print(f"{context.prefix}: {reason}", file=sys.stderr)
    return None, _check_result(context.check, start, "fail" if child.execution == "budget" else "unsupported",
                               execution=child.execution, budget_seconds=budget, reason=reason,
                               diagnostics=child.diagnostics())


def _validate_report_version(document: Any, version: str) -> None:
    if isinstance(document, dict) and "emacs_version" in document:
        reported = document["emacs_version"]
        if reported != version:
            shown = _version_excerpt(reported if isinstance(reported, str) else repr(reported))
            raise ValueError(f"Emacs version {version} from preflight, got {shown!r}")


def _resolved_path(root: Path, target: Path, path: Path, key: str, kind: str) -> Path:
    try:
        return (root / target).resolve()
    except (OSError, RuntimeError) as error:
        raise _config_error(path, key, f"a repository-relative {kind}", str(error)) from error


def _safe_relative(value: str, target: Path) -> bool:
    return bool(value.strip()) and "\0" not in value and not target.is_absolute() and ".." not in target.parts


def _relative_path(root: Path | None, value: str, path: Path, key: str, kind: str) -> None:
    if root is None:
        return
    target = Path(value)
    if not _safe_relative(value, target):
        raise _config_error(path, key, f"a repository-relative {kind}", repr(value))
    resolved = _resolved_path(root, target, path, key, kind)
    if not resolved.is_relative_to(root.resolve()):
        raise _config_error(path, key, f"a repository-relative {kind}", repr(value))
    exists = resolved.is_file() if kind == "regular file" else resolved.is_dir()
    if not exists:
        raise _config_error(path, key, f"a {kind}", f"{value!r} is missing or not a {kind}")


def _common_spec(
    raw: dict[str, Any], root: Path | None, path: Path, key: str
) -> tuple[tuple[str, ...], str, int]:
    load_path = _optional_string_list(raw, "load_path", path, f"{key}.load_path")
    for index, directory in enumerate(load_path):
        _relative_path(root, directory, path, f"{key}.load_path[{index}]", "directory")
    emacs = _string(raw, "emacs", path, f"{key}.emacs") if "emacs" in raw else "emacs"
    if "\0" in emacs:
        raise _config_error(path, f"{key}.emacs", "a command without NUL", repr(emacs))
    budget = _integer(raw, "budget_seconds", path, f"{key}.budget_seconds",
                      default=DEFAULT_TESTS_BUDGET_SECONDS, minimum=1)
    return load_path, emacs, budget


def parse_spec(raw: dict[str, Any], root: Path | None, path: Path, key: str) -> ElispTestsSpec:
    suite = _string(raw, "suite", path, f"{key}.suite")
    _relative_path(root, suite, path, f"{key}.suite", "regular file")
    return ElispTestsSpec(suite, *_common_spec(raw, root, path, key))


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
    return isinstance(item["symbol"], str) and isinstance(item["file"], str) and bool(item["file"])


def _definition_file(item: dict[str, Any], selected: list[str]) -> bool:
    filename = Path(item["file"])
    if filename.is_absolute() or ".." in filename.parts:
        return False
    return item["file"] in selected


def _definition_counts(item: dict[str, Any]) -> bool:
    return (all(_count(item[key]) for key in ("position", "stop_points", "reached"))
            and item["position"] > 0 and item["reached"] <= item["stop_points"])


def _definition(item: Any, selected: list[str]) -> bool:
    return (_definition_shape(item) and _definition_names(item)
            and _definition_file(item, selected) and _definition_counts(item))


def _validate_shape(document: Any) -> None:
    if not isinstance(document, dict):
        raise ValueError("a JSON object")
    keys = {
        "emacs_version", "selected", "passed", "failed", "skipped", "selected_ids",
        "test_results", "definitions",
    }
    if set(document) != keys:
        raise ValueError(f"keys {sorted(keys)}, got {sorted(document)}")


def _validate_counts(document: dict[str, Any]) -> None:
    if not all(_count(document[key]) for key in ("selected", "passed", "failed", "skipped")):
        raise ValueError("non-negative integer test counts")


def _result_keys(row: Any, label: str) -> None:
    keys = {"position", "id", "outcome", "expected", "duration_seconds"}
    if not isinstance(row, dict) or type(row.get("expected")) is not bool:
        raise ValueError(f"{label}: expected a result row with boolean expectedness")
    if not row["expected"]:
        keys.add("condition")
    if set(row) != keys:
        raise ValueError(f"{label}: expected result keys {sorted(keys)}, got {sorted(row)}")


def _result_duration(duration: Any) -> bool:
    return type(duration) in (int, float) and 0 <= duration <= sys.float_info.max


def _validate_unexpected_result(row: dict, label: str) -> None:
    condition = row["condition"]
    if row["outcome"] == "ert-test-skipped" or not isinstance(condition, str) or not condition:
        raise ValueError(f"{label}: invalid unexpected result condition")


def _validate_result(row: Any, position: int, name: str) -> None:
    label = f"ERT selection position {position} ({name!r})"
    _result_keys(row, label)
    if type(row["position"]) is not int or (row["position"], row["id"]) != (position, name):
        raise ValueError(f"{label}: got position {row['position']!r} and ID {row['id']!r}")
    _validate_result_outcome(row, label)


def _validate_result_outcome(row: dict, label: str) -> None:
    outcome = row["outcome"]
    if not isinstance(outcome, str) or outcome not in ERT_OUTCOMES:
        raise ValueError(f"{label}: invalid native outcome {outcome!r}")
    if not _result_duration(row["duration_seconds"]):
        raise ValueError(f"{label}: invalid duration {row['duration_seconds']!r}")
    if not row["expected"]:
        _validate_unexpected_result(row, label)


def _result_class(row: dict) -> str | None:
    category = ERT_OUTCOMES[row["outcome"]]
    if category == "completed":
        return "passed" if row["expected"] else "failed"
    return category


def _validate_selected_ids(ids: list) -> None:
    seen = set()
    for position, name in enumerate(ids):
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError(f"ERT selection position {position}: invalid or duplicate selected ID {name!r}")
        seen.add(name)


def _result_counts(ids: list, rows: list) -> dict:
    counts = dict.fromkeys(("passed", "failed", "skipped"), 0)
    for position, name in enumerate(ids):
        if position >= len(rows):
            raise ValueError(f"ERT selection position {position} ({name!r}): missing result")
        row = rows[position]
        _validate_result(row, position, name)
        category = _result_class(row)
        if category is not None:
            counts[category] += 1
    if len(rows) > len(ids):
        raise ValueError(f"unexpected ERT result at position {len(ids)}: {rows[len(ids)]!r}")
    return counts


def _validate_results(document: dict[str, Any]) -> None:
    ids, rows = document["selected_ids"], document["test_results"]
    if not isinstance(ids, list) or not isinstance(rows, list):
        raise ValueError("expected selected_ids and test_results arrays")
    _validate_selected_ids(ids)
    counts = _result_counts(ids, rows)
    native_counts = {key: document[key] for key in counts}
    if (len(ids), counts) != (document["selected"], native_counts):
        raise ValueError(f"ERT result counts disagree with native totals: selected={len(ids)}, {counts}")


def _validate_definitions(document: dict[str, Any], selected: list[str]) -> None:
    definitions = document["definitions"]
    if not isinstance(definitions, list) or not all(_definition(item, selected) for item in definitions):
        raise ValueError("a list of valid instrumented definitions")


def validate_document(document: Any, selected: list[str]) -> dict[str, Any]:
    """Validate a child measurement, raising ValueError on malformed evidence."""
    _validate_shape(document)
    _validate_counts(document)
    _validate_results(document)
    _validate_definitions(document, selected)
    return document


def _error_document(document: Any) -> bool:
    if not isinstance(document, dict) or set(document) != {"error"}:
        return False
    error = document["error"]
    return isinstance(error, str) and bool(error)


def _read_document(path: Path, selected: list[str], version: str) -> dict[str, Any]:
    try:
        document = load_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise ValueError(f"a JSON result document, got {error}") from error
    _validate_report_version(document, version)
    if _error_document(document):
        return document
    try:
        validated = validate_document(document, selected)
        path.write_bytes(json.dumps(
            validated, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8"))
        return validated
    except (OSError, ValueError) as error:
        raise ValueError(f"a valid result, got {error}") from error


def apply_document(result: Any, document: dict[str, Any]) -> None:
    """Attach test counts and definition evidence to a check result."""
    result.tests_ran = document["selected"]
    result.tests_skipped = document["skipped"]
    result.measurement = {"tests": document["selected"] - document["skipped"]}
    result.tool = {"name": "Emacs", "version": document["emacs_version"]}
    result.adapter_data = document["definitions"]
    result.report_fields = {"definitions": document["definitions"], "test_results": document["test_results"]}


def _unexpected_results(document: dict[str, Any]) -> list[dict]:
    return [row for row in document["test_results"] if not row["expected"]]


def _verdict(document: dict[str, Any]) -> str | None:
    unexpected = _unexpected_results(document)
    if unexpected:
        conditions = "; ".join(f"{row['id']}: {row['condition']}" for row in unexpected)
        return f"unexpected test results: {conditions}"
    if document["selected"] == document["skipped"]:
        return f"no test executed: {document['selected']} selected, {document['skipped']} skipped"
    if document["selected"] != document["passed"] + document["failed"] + document["skipped"]:
        return "ERT did not complete all selected tests"
    return None


def _temporary() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="qg-elisp-")


def _failure_findings(document: dict[str, Any], suite: str) -> list[FindingResult]:
    names = sorted(row["id"] for row in _unexpected_results(document))
    return [
        FindingResult(
            subject=name, value=1, bound=None, threshold=0, baseline_reason=None,
            blocking=True, location=suite,
        )
        for name in names
    ]


def _finish(context: Any, start: float, run_result: Any, document: dict[str, Any],
            evidence: Path) -> Any:
    from .checks import _check_result, _combined_reason, _tests_result

    check, spec = context.check, context.check.spec
    diagnostics = run_result.diagnostics()
    if "error" in document:
        return _tests_result(
            check, spec, start, context.prefix, f"child exit {run_result.returncode}: {document['error']}",
            diagnostics=diagnostics, report=False,
        )
    reason = _verdict(document)
    outcome = "fail" if reason else "pass"
    if run_result.returncode != 0:
        reason = _combined_reason(
            f"expected child exit 0 with a result, got exit {run_result.returncode}", reason,
        )
        outcome = "unsupported"
    result = _check_result(check, start, outcome, budget_seconds=spec.budget_seconds,
                           diagnostics=diagnostics, reason=reason, evidence_path=evidence)
    result.findings = _failure_findings(document, spec.suite)
    apply_document(result, document)
    return result


def _execution_failure(context: Any, start: float, run_result: Any) -> Any:
    from .checks import _tests_result

    check, prefix, spec = context.check, context.prefix, context.check.spec
    outcome = execution_outcome(run_result.execution)
    if outcome.budget:
        return _tests_result(
            check, spec, start, prefix, "Emacs exceeded its budget",
            execution=outcome.name, diagnostics=run_result.diagnostics(), report=False,
        )
    if outcome.signal:
        return _tests_result(
            check, spec, start, prefix, f"Emacs terminated by signal {-run_result.returncode}",
            outcome="unsupported", execution=outcome.name, diagnostics=run_result.diagnostics(), report=False,
        )
    if outcome.error:
        reason = f"expected Emacs command {spec.emacs!r}, got {run_result.error}"
        return _tests_result(check, spec, start, prefix, reason, outcome="unsupported",
                             execution=outcome.name, diagnostics=run_result.diagnostics(), report=False)
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


def _report_finish(context: Any, result: Any, document: dict[str, Any],
                   child: Any, temporary_reason: str | None) -> Any:
    from .checks import _merge_temporary_reason

    result = _merge_temporary_reason(result, temporary_reason)
    if "error" in document or child.returncode != 0:
        print(f"{context.prefix}: {result.reason}", file=sys.stderr)
    elif result.reason is not None:
        print(f"{context.prefix}: {result.reason} (Emacs {document['emacs_version']})",
              file=sys.stderr)
    else:
        print(f"{context.prefix}: passed ({result.measurement['tests']} tests, "
              f"Emacs {document['emacs_version']}, {result.duration_seconds:.2f}s)",
              flush=True)
    return result


def run_tests(context: Any) -> Any:
    """Run the configured suite and return its check result and evidence."""
    from .checks import (
        _finish_test_result,
        _finish_temporary,
        _select_files,
        _temporary_reason,
        _temporary_test_directory,
        _tests_result,
    )

    version, failure = probe_version(context)
    if failure is not None:
        return failure
    start = time.monotonic()
    spec = context.check.spec
    selected, _classes = _select_files(context.config, context.check, context.files, context.classes)
    collision = _suite_collision(context, selected, start)
    if collision is not None:
        return collision
    directory = context.evidence_dir
    stage = _stage(directory)
    evidence = directory / "result.json"
    temporary = _temporary_test_directory()
    environment = os.environ.copy()
    environment["TMPDIR"] = str(temporary)
    mark_step("Emacs test command")
    try:
        child = run(_command(spec, context.root, selected, stage, evidence), cwd=context.root,
                    env=environment, budget_seconds=spec.budget_seconds)
    finally:
        temporary_paths = _finish_temporary(temporary)
    temporary_reason = _temporary_reason(temporary_paths)
    failure = _execution_failure(context, start, child)
    if failure is not None:
        return _finish_test_result(failure, temporary_reason, context.prefix)
    try:
        mark_step("Emacs result validation")
        document = _read_document(evidence, selected, version)
    except ValueError as error:
        reason = (
            f"{evidence.name}: expected {error}; child exit {child.returncode}, execution {child.execution}"
        )
        result = _tests_result(context.check, spec, start, context.prefix, reason, outcome="unsupported",
                               execution=child.execution, diagnostics=child.diagnostics(), report=False)
        return _finish_test_result(result, temporary_reason, context.prefix)
    result = _finish(context, start, child, document, evidence)
    return _report_finish(context, result, document, child, temporary_reason)
