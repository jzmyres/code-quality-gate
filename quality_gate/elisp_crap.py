"""Join the editor's Emacs Lisp complexity with earlier Edebug evidence."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .elisp_tests import _lisp_string, _temporary
from .policy import GateError
from .ratchet import Domain, Finding, Location
from .runner import analysis_step, mark_step, record_diagnostics, run


def selection_failure(context: Any, start: float) -> Any:
    """Refuse files whose classes do not also request the test check."""
    from .checks import _check_result, _select_files

    selected, _names = _select_files(context.config, context.check, context.files, context.classes)
    required = context.check.spec.requires
    for name in selected:
        class_def = context.config.classes[context.classes[name]]
        if required not in class_def.checks:
            message = (f"check {context.check.id}: {name} must also be instrumented by "
                       f"required check {required}")
            print(f"{context.prefix}: {message}", file=sys.stderr)
            return _check_result(context.check, start, "error", execution="error", reason=message,
                                 configuration_error=True)
    return None


def _command(emacs: str, root: Path, files: list[str], result: Path) -> list[str]:
    helper = Path(__file__).with_name("elisp") / "qg-elisp-complexity.el"
    names = " ".join(_lisp_string(name) for name in files)
    form = (f"(qg-elisp-complexity-run {_lisp_string(str(root) + os.sep)} '({names}) "
            f"{_lisp_string(str(result))})")
    return [emacs, "-Q", "--batch", "-l", str(helper), "--eval", form]


def _definition_shape(item: Any) -> bool:
    return isinstance(item, dict) and set(item) == {"file", "name", "line", "end_line", "start", "end", "cc"}


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _definition_numbers(item: dict[str, Any]) -> bool:
    values = [item[key] for key in ("line", "end_line", "start", "end", "cc")]
    return (all(_positive_integer(value) for value in values)
            and item["line"] <= item["end_line"] and item["start"] < item["end"])


def _valid_definition(item: Any, selected: list[str]) -> bool:
    return (_definition_shape(item) and item["file"] in selected
            and isinstance(item["name"], str) and _definition_numbers(item))


def _error_document(document: Any) -> bool:
    return (isinstance(document, dict) and set(document) == {"error"}
            and isinstance(document["error"], str) and bool(document["error"]))


def _valid_document(document: Any, selected: list[str]) -> bool:
    return (isinstance(document, dict) and set(document) == {"definitions"}
            and isinstance(document["definitions"], list)
            and all(_valid_definition(item, selected) for item in document["definitions"]))


def _read_result(path: Path, selected: list[str]) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise GateError(f"expected a complexity JSON result, got {error}") from error
    if _error_document(document):
        return document
    if not _valid_document(document, selected):
        raise GateError("expected valid complexity definitions from Emacs")
    return document


def _within_span(
    definition: dict[str, Any], entry: dict[str, Any], file_keys: dict[str, Any],
) -> bool:
    position = entry["position"]
    return (file_keys[definition["file"]] == file_keys[entry["file"]]
            and definition["start"] <= position and position < definition["end"])


def _identity(definition: dict[str, Any]) -> str:
    return f"{definition['file']}:{definition['name']}"


def _duplicates(definitions: list[dict[str, Any]]) -> list[str]:
    lines: dict[str, int] = {}
    failures = []
    for definition in definitions:
        identity = _identity(definition)
        line = definition["line"]
        if identity in lines:
            failures.append(f"duplicate function identity {identity}: {definition['file']}:{lines[identity]} "
                            f"and {definition['file']}:{line}")
        else:
            lines[identity] = line
    return failures


def _file_key(root: Path, name: str) -> tuple[int, int] | str:
    try:
        stat = (root / name).stat()
    except OSError:
        return name
    return stat.st_dev, stat.st_ino


def _file_keys(
    root: Path, definitions: list[dict[str, Any]], evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    names = {item["file"] for item in definitions + evidence}
    return {name: _file_key(root, name) for name in names}


def _counts(
    root: Path, definitions: list[dict[str, Any]], evidence: list[dict[str, Any]],
) -> list[list[int]]:
    file_keys = _file_keys(root, definitions, evidence)
    counts = [[0, 0] for _ in definitions]
    for entry in evidence:
        for index, definition in enumerate(definitions):
            if _within_span(definition, entry, file_keys):
                counts[index][0] += entry["stop_points"]
                counts[index][1] += entry["reached"]
                break
    return counts


def _finding(definition: dict[str, Any], points: int, hits: int) -> Finding | None:
    if points == 0:
        return None
    cc = definition["cc"]
    value = cc * cc * (1 - hits / max(points, 1)) ** 3 + cc
    path, line = definition["file"], definition["line"]
    return Finding(_identity(definition), value, f"{path}:{line}",
                   {"cc": cc, "points": points, "hits": hits},
                   (Location(path, line, definition["end_line"]),))


def _analyse(
    root: Path, definitions: list[dict[str, Any]], evidence: list[dict[str, Any]]
) -> tuple[list[Finding], list[str]]:
    failures = _duplicates(definitions)
    if failures:
        return [], failures
    findings = []
    for definition, (points, hits) in zip(definitions, _counts(root, definitions, evidence), strict=True):
        finding = _finding(definition, points, hits)
        if finding is None:
            failures.append(f"{_identity(definition)}: unmeasured (no Edebug stop point in this definition "
                            f"at {definition['file']}:{definition['line']})")
        else:
            findings.append(finding)
    return sorted(findings, key=lambda item: item.subject), failures


def _failed_measurement(context: Any, start: float, messages: list[str]) -> Any:
    from .checks import _ratchet_result, _tail_diagnostics

    for message in messages:
        print(f"{context.prefix}: {message}", file=sys.stderr)
    diagnostics = _tail_diagnostics(messages, argv=None, exit_code=1)
    return _ratchet_result(context.check, start, "fail", diagnostics=diagnostics,
                           reason=diagnostics.output_tail)


def _child_failure(context: Any, start: float, child: Any) -> Any:
    from .checks import _ratchet_result

    if child.execution == "budget":
        reason, outcome = "Emacs complexity command exceeded its budget", "fail"
    else:
        detail = child.error or child.output_tail.decode("utf-8", "replace") or f"exit {child.returncode}"
        reason, outcome = f"Emacs complexity command failed: {detail}", "unsupported"
    print(f"{context.prefix}: {reason}", file=sys.stderr)
    return _ratchet_result(context.check, start, outcome, execution=child.execution,
                           diagnostics=child.diagnostics(), reason=reason)


def _complexity_document(context: Any, selected: list[str], start: float, child: Any, result: Path) -> Any:
    from .checks import _ratchet_error

    try:
        document = analysis_step("Emacs complexity result", _read_result, result, selected)
    except GateError as error:
        if child.returncode != 0:
            return None, _child_failure(context, start, child)
        return None, _ratchet_error(context.check, start, context.prefix, error)
    if "error" in document:
        return None, _failed_measurement(context, start, [document["error"]])
    if child.returncode != 0:
        return None, _child_failure(context, start, child)
    return document["definitions"], None


def _complexity(context: Any, selected: list[str], start: float) -> tuple[Any, Any]:
    from .checks import CLONE_BUDGET_SECONDS

    required = context.config.checks[context.check.spec.requires]
    with _temporary() as temporary:
        result = Path(temporary) / "result.json"
        mark_step("Emacs complexity command")
        child = run(_command(required.spec.emacs, context.root, selected, result),
                    cwd=context.root, budget_seconds=CLONE_BUDGET_SECONDS)
        record_diagnostics(child.diagnostics())
        if child.execution != "completed":
            return None, _child_failure(context, start, child)
        return _complexity_document(context, selected, start, child, result)


def _required(context: Any, start: float) -> tuple[Any, Any]:
    from .checks import _ratchet_result

    name = context.check.spec.requires
    required = context.prior.get(name)
    if required is None or required.outcome != "pass":
        reason = f"coverage unreliable: {name} did not pass"
    elif required.definitions is None:
        reason = f"coverage unreliable: {name} produced no Edebug evidence"
    else:
        return required.definitions, None
    print(f"{context.prefix}: {reason}", file=sys.stderr)
    return None, _ratchet_result(context.check, start, "unsupported", reason=reason)


def _domain(selected: list[str], files: list[str], entries: list[Any]) -> Domain:
    # Both paths and symbol names can contain colons.  Use the longest actual
    # inventory path so an unselected file cannot masquerade as a symbol.
    subjects = []
    for entry in entries:
        candidates = [name for name in files if entry.subject.startswith(f"{name}:")]
        if candidates and max(candidates, key=len) in selected:
            subjects.append(entry.subject)
    return Domain.of_subjects(subjects, "the selected files")


def _ratchet(context: Any, start: float, selected: list[str], findings: list[Finding]) -> Any:
    from .checks import _baseline_entries, _evaluate_ratchet, _ratchet_error, _ratchet_result

    try:
        entries = analysis_step("baseline loading", _baseline_entries, context.check)
    except GateError as error:
        return _ratchet_error(context.check, start, context.prefix, error)
    domain = analysis_step("Elisp measured domain", _domain, selected, context.files, entries)
    ratchet, failure = _evaluate_ratchet(findings, entries, context.check, context.prefix, domain)
    if ratchet is None:
        return _ratchet_result(context.check, start, failure or "error", reason=failure)
    if ratchet.satisfied:
        print(f"{context.prefix}: {len(findings)} functions within threshold", flush=True)
    return _ratchet_result(context.check, start, ratchet.outcome, ratchet=ratchet,
                           measurement={"functions": len(findings)})


def run_crap(context: Any) -> Any:
    """Read complexity once and score it against an earlier Edebug run."""
    from .checks import _adapter_selection, _class_text

    _spec, start, selected, names = _adapter_selection(context)
    failure = analysis_step("Elisp coverage selection", selection_failure, context, start)
    if failure is not None:
        return failure
    evidence, failure = analysis_step("Edebug evidence validation", _required, context, start)
    if failure is not None:
        return failure
    if not selected:
        return _failed_measurement(context, start, [f"no files selected (classes: {_class_text(names)}); "
                                                     "zero inputs is not a pass"])
    definitions, failure = _complexity(context, selected, start)
    if failure is not None:
        return failure
    findings, failures = analysis_step("Elisp attribution", _analyse, context.root, definitions, evidence)
    if failures:
        return _failed_measurement(context, start, failures)
    return _ratchet(context, start, selected, findings)
