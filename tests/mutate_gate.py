#!/usr/bin/env python3
"""Run a fixed set of decision mutations against isolated copies of the gate."""

from __future__ import annotations

import ast
import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Decision:
    name: str
    module: str
    function: str
    operator: str
    target: str
    reason: str


# Each entry specifies exactly one deliberate fault, not every syntactic
# mutation in the function. Exact AST source matches make drift an error.
DECISIONS = (
    Decision(
        "elisp_compile_warning",
        "quality_gate/elisp_lint.py",
        "_compile_failed",
        "comparison",
        'len(document["failed"]) > 0',
        "A compiler warning or error fails the compile check.",
    ),
    Decision(
        "elisp_checkdoc_issue",
        "quality_gate/elisp_lint.py",
        "_checkdoc_failed",
        "comparison",
        'len(document["issues"]) > 0',
        "A checkdoc issue fails the documentation check.",
    ),
    Decision(
        "elisp_unmeasured",
        "quality_gate/elisp_crap.py",
        "_finding",
        "comparison",
        "points == 0",
        "A definition without Edebug stop points is unmeasured.",
    ),
    Decision(
        "elisp_attribution_end",
        "quality_gate/elisp_crap.py",
        "_within_span",
        "comparison",
        'position < definition["end"]',
        "A definition's end position is excluded from attribution.",
    ),
    Decision(
        "elisp_no_executed_tests",
        "quality_gate/elisp_tests.py",
        "_verdict",
        "comparison",
        'document["selected"] == document["skipped"]',
        "An ERT run with no executed test fails.",
    ),
    Decision(
        "baseline_max_bound",
        "quality_gate/ratchet.py",
        "_within",
        "comparison",
        "value <= bound",
        "A maximum exception includes its exact bound.",
    ),
    Decision(
        "verification_min_floor",
        "quality_gate/ratchet.py",
        "_within",
        "comparison",
        "value >= bound",
        "The executed-test floor includes its exact bound.",
    ),
    Decision(
        "crap_threshold",
        "quality_gate/ratchet.py",
        "_outside",
        "comparison",
        "value > threshold",
        "CRAP and other maximum thresholds include equality.",
    ),
    Decision(
        "baseline_expiry",
        "quality_gate/ratchet.py",
        "_scan_entries",
        "comparison",
        "entry.expires < today",
        "An exception expires only after its expiry date.",
    ),
    Decision(
        "baseline_reason",
        "quality_gate/ratchet.py",
        "_valid_entry",
        "negate",
        "not entry.reason.strip()",
        "An exception needs a non-empty reason.",
    ),
    Decision(
        "baseline_max_satisfaction",
        "quality_gate/ratchet.py",
        "_max_verdict",
        "negate",
        "(not outside) or valid",
        "A maximum within the threshold passes without an exception.",
    ),
    Decision(
        "baseline_domain",
        "quality_gate/ratchet.py",
        "_record_unmeasured",
        "negate",
        "domain.contains(entry.subject)",
        "Only a complete domain resolves an absent entry.",
    ),
    Decision(
        "prune_refusal",
        "quality_gate/ratchet.py",
        "pruned_entries",
        "remove_raise",
        'raise GateError("cannot prune while the check fails")',
        "A failing ratchet cannot be pruned.",
    ),
    Decision(
        "prune_direction",
        "quality_gate/ratchet.py",
        "_prune_entry",
        "comparison",
        'direction == "min"',
        "Pruning raises floors and lowers ceilings.",
    ),
    Decision(
        "prune_check_satisfaction",
        "quality_gate/checks.py",
        "_prune_allowed",
        "negate",
        "target.is_satisfied()",
        "A requested prune requires a satisfied check.",
    ),
    Decision(
        "prune_exit",
        "quality_gate/checks.py",
        "_decision_exit_code",
        "negate",
        'not prune["performed"]',
        "A refused prune must exit unsuccessfully.",
    ),
    Decision(
        "gate_builtin_failure",
        "quality_gate/gate_result.py",
        "_builtins_pass",
        "comparison",
        'result.kind in ("inventory", "hygiene")',
        "Inventory and hygiene failures reject the gate.",
    ),
    Decision(
        "gate_enforced_failure",
        "quality_gate/gate_result.py",
        "_enforced_checks_pass",
        "comparison",
        'result.enforcement == "enforced"',
        "Every enforced check must be satisfied.",
    ),
    Decision(
        "gate_obligation",
        "quality_gate/gate_result.py",
        "_run_passes",
        "comparison",
        'item["status"] != "unsatisfied"',
        "An unsatisfied obligation rejects the gate.",
    ),
    Decision(
        "trust_authorization",
        "quality_gate/trust.py",
        "_declared_status",
        "comparison",
        "item.path in allowed",
        "Only explicitly authorized protected changes take effect.",
    ),
    Decision(
        "trust_min_baseline_merge",
        "quality_gate/trust.py",
        "_merge_revision_entry",
        "comparison",
        'direction == "min"',
        "An omitted candidate minimum cannot remove the trusted floor.",
    ),
    Decision(
        "trust_non_regular_input",
        "quality_gate/trust.py",
        "_read_regular",
        "remove_raise",
        "raise _candidate_error(path, _kind_name(mode))",
        "Protected inputs must be regular files.",
    ),
    Decision(
        "trust_gate_location",
        "quality_gate/trust.py",
        "_refuse_inside",
        "remove_raise",
        'raise UsageError(\n            f"--policy-from: the gate program at {gate_root} lies inside "\n'
        '            f"the candidate root {root}; run a trusted copy of the gate "\n'
        '            "outside the candidate"\n        )',
        "A trusted gate must be outside the candidate.",
    ),
    Decision(
        "trust_identity_comparison",
        "quality_gate/trust.py",
        "_section_problems",
        "comparison",
        "old.get(name) != new.get(name)",
        "Changes to a gate file or tool payload are errors.",
    ),
)


class MutationError(Exception):
    pass


@dataclass(frozen=True)
class Outcome:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class Report:
    outcomes: tuple[Outcome, ...]
    errors: tuple[str, ...]
    probe_seconds: float = 0.0
    total_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        return (
            bool(self.outcomes) and not self.errors and all(item.status == "killed" for item in self.outcomes)
        )


@dataclass(frozen=True)
class _Probe:
    selections: dict[str, tuple[str, ...]]
    unattributed: frozenset[str]
    ids: tuple[str, ...]
    failure: str | None


def _function(tree: ast.Module, decision: Decision) -> ast.FunctionDef | ast.AsyncFunctionDef:
    body = tree.body
    names = decision.function.split(".")
    for index, name in enumerate(names):
        nodes = [
            item
            for item in body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
        ]
        if len(nodes) != 1:
            raise MutationError(f"{decision.name}: function {decision.function} does not exist uniquely")
        node = nodes[0]
        if index < len(names) - 1:
            if not isinstance(node, ast.ClassDef):
                raise MutationError(f"{decision.name}: {name} is not a class")
            body = node.body
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise MutationError(f"{decision.name}: {decision.function} is not a function")
    return node


def _nodes(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """Do not accidentally select a node in a nested function or class."""
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(reversed(list(ast.iter_child_nodes(node))))


_FLIPS = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}


def _replacement(node: ast.AST, decision: Decision) -> str | None:
    if decision.operator == "comparison" and isinstance(node, ast.Compare) and len(node.ops) == 1:
        flipped = _FLIPS.get(type(node.ops[0]))
        if flipped is not None:
            changed = copy.deepcopy(node)
            changed.ops[0] = flipped()
            return ast.unparse(changed)
    if decision.operator == "negate" and isinstance(node, ast.expr):
        return f"not ({decision.target})"
    if decision.operator == "opposite_return" and isinstance(node, ast.Return):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
            return f"return {not node.value.value}"
    if decision.operator == "remove_raise" and isinstance(node, ast.Raise):
        return "pass"
    return None


def _offset(source: str, line: int, column: int) -> int:
    # AST columns are UTF-8 byte offsets, not Unicode character offsets.
    lines = source.splitlines(keepends=True)
    prefix = lines[line - 1].encode("utf-8")[:column].decode("utf-8")
    return sum(len(item) for item in lines[: line - 1]) + len(prefix)


def _target_match(source: str, decision: Decision) -> tuple[ast.AST, str]:
    try:
        tree = ast.parse(source, filename=decision.module)
    except SyntaxError as error:
        raise MutationError(f"{decision.name}: cannot parse {decision.module}: {error}") from error
    function = _function(tree, decision)
    matches = [
        (node, _replacement(node, decision))
        for node in _nodes(function)
        if ast.get_source_segment(source, node) == decision.target
    ]
    matches = [(node, replacement) for node, replacement in matches if replacement is not None]
    if len(matches) != 1:
        raise MutationError(
            f"{decision.name}: {decision.function}: expected one applicable "
            f"{decision.operator} mutation for {decision.target!r}, found {len(matches)}"
        )
    return matches[0]


def mutate(source: str, decision: Decision) -> str:
    node, replacement = _target_match(source, decision)
    start = _offset(source, node.lineno, node.col_offset)
    end = _offset(source, node.end_lineno, node.end_col_offset)
    changed = source[:start] + replacement + source[end:]
    try:
        compile(changed, decision.module, "exec")
    except SyntaxError as error:
        raise MutationError(f"{decision.name}: generated invalid Python: {error}") from error
    return changed


def _reached_edits(source: str, decisions: tuple[Decision, ...]) -> list[tuple[int, int, str]]:
    edits = []
    for decision in decisions:
        node, _replacement = _target_match(source, decision)
        start = _offset(source, node.lineno, node.col_offset)
        end = _offset(source, node.end_lineno, node.end_col_offset)
        name = repr(decision.name)
        if isinstance(node, ast.stmt):
            edits.append((start, start, f"_qg_mutation_record('reached', {name}); "))
        else:
            edits.append((start, end, f"_qg_mutation_reached({name}, ({source[start:end]}))"))
    return edits


def _insert_reached(source: str, decisions: tuple[Decision, ...]) -> str:
    for start, end, replacement in sorted(_reached_edits(source, decisions), reverse=True):
        source = source[:start] + replacement + source[end:]
    return source


def _instrument(
    source: str, marker: Path, token: str, reached: tuple[Decision, ...]
) -> str:
    tree = ast.parse(source)
    prefix = 0
    for index, node in enumerate(tree.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            prefix = node.end_lineno
        elif isinstance(node, ast.ImportFrom) and node.module == "__future__":
            prefix = node.end_lineno
        else:
            break
    source = _insert_reached(source, reached)
    lines = source.splitlines(keepends=True)
    preamble = (
        "\n"
        "import json as _qg_mutation_json, os as _qg_mutation_os\n"
        f"_qg_mutation_marker = {str(marker)!r}\n"
        f"_qg_mutation_token = {token!r}\n"
        "def _qg_mutation_record(event, detail=''):\n"
        "    test = _qg_mutation_os.environ.get('QG_MUTATION_TEST') or 'unattributed'\n"
        "    with open(_qg_mutation_marker, 'a', encoding='utf-8') as _qg_mutation_file:\n"
        "        record = {'token': _qg_mutation_token, 'event': event, 'detail': detail, 'test': test}\n"
        "        _qg_mutation_file.write(_qg_mutation_json.dumps(record) + '\\n')\n"
        "def _qg_mutation_reached(name, value):\n"
        "    _qg_mutation_record('reached', name)\n"
        "    return value\n"
    )
    return "".join(lines[:prefix]) + preamble + "".join(lines[prefix:])


def _prepare(source_root: Path, decisions: tuple[Decision, ...]) -> list[tuple[Decision, str]]:
    if not decisions:
        raise MutationError("zero mutants generated: the decision list is empty")
    names: set[str] = set()
    prepared = []
    for decision in decisions:
        if not decision.name or not decision.reason.strip() or decision.name in names:
            raise MutationError(f"invalid or duplicate decision name/reason: {decision.name!r}")
        names.add(decision.name)
        module = Path(decision.module)
        if module.is_absolute() or ".." in module.parts or module.suffix != ".py":
            raise MutationError(f"{decision.name}: invalid module path {decision.module!r}")
        try:
            source = (source_root / module).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise MutationError(f"{decision.name}: cannot read {module}: {error}") from error
        prepared.append((decision, mutate(source, decision)))
    return prepared


_CURRENT_TEST_ENV = "QG_MUTATION_TEST"


class _TestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ids: list[str] = []
        self.previous_tests: list[str | None] = []

    def startTest(self, test):
        self.ids.append(test.id())
        self.previous_tests.append(os.environ.get(_CURRENT_TEST_ENV))
        os.environ[_CURRENT_TEST_ENV] = test.id()
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        previous = self.previous_tests.pop()
        if previous is None:
            os.environ.pop(_CURRENT_TEST_ENV, None)
        else:
            os.environ[_CURRENT_TEST_ENV] = previous


def _filter_suite(suite: unittest.TestSuite, selected: set[str]) -> unittest.TestSuite:
    kept = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            child = _filter_suite(test, selected)
            if child.countTestCases():
                kept.append(child)
        elif test.id() in selected:
            kept.append(test)
    return unittest.TestSuite(kept)


def _suite(
    root: Path,
    tests: str,
    report_path: Path,
    selected: list[str] | None = None,
    failfast: bool = False,
) -> int:
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / tests))
    suite = unittest.defaultTestLoader.discover(str(root / tests))
    if selected is not None:
        suite = _filter_suite(suite, set(selected))
    result = unittest.TextTestRunner(resultclass=_TestResult, verbosity=1, failfast=failfast).run(suite)
    report = {
        "ids": result.ids,
        "failures": [test.id() for test, _ in result.failures],
        "errors": [test.id() for test, _ in result.errors],
        "skipped": [test.id() for test, _ in result.skipped],
        "expected_failures": [test.id() for test, _ in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


def _run_suite(
    root: Path,
    tests: str,
    work: Path,
    timeout: float,
    driver: Path,
    *,
    selected: tuple[str, ...] | None = None,
    failfast: bool = False,
) -> tuple[str, dict, str]:
    result_path = work / "suite.json"
    command = [
        sys.executable,
        "-I",
        str(driver),
        "--suite",
        str(root),
        tests,
        str(result_path),
    ]
    if selected is not None:
        selection_path = work / "selected.json"
        selection_path.write_text(json.dumps(list(selected)), encoding="utf-8")
        command.extend(["--selected", str(selection_path)])
    if failfast:
        command.append("--failfast")
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("QG_PYTHON", _CURRENT_TEST_ENV) and not key.startswith("COVERAGE_")
    }
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True
            )
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                return "timed out", {}, f"suite exceeded {timeout:g} seconds"
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(max(0, size - 5000))
            tail = output.read().decode("utf-8", errors="replace")
    except OSError as error:
        return "error", {}, f"cannot execute suite: {error}"
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        fields = (
            "ids",
            "failures",
            "errors",
            "skipped",
            "expected_failures",
            "unexpected_successes",
        )
        if not isinstance(result, dict) or any(
            not isinstance(result.get(key), list) or not all(isinstance(item, str) for item in result[key])
            for key in fields
        ):
            raise ValueError("invalid suite report")
    except (OSError, UnicodeError, ValueError) as error:
        return "error", {}, f"missing or invalid suite report: {error}; exit {process.returncode}; {tail}"
    if process.returncode not in (0, 1) or bool(process.returncode) != bool(
        result["failures"] or result["errors"] or result["unexpected_successes"]
    ):
        return "error", result, f"unexpected suite exit {process.returncode}; {tail}"
    if result["skipped"] or result["expected_failures"]:
        return "error", result, "suite has skipped or expected-failure tests"
    if not result["ids"]:
        return "error", result, "suite ran zero tests"
    if result["failures"] or result["errors"] or result["unexpected_successes"]:
        return "failed", result, tail
    return "passed", result, tail


def _copy(source_root: Path, destination: Path) -> None:
    shutil.copytree(
        source_root,
        destination,
        ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__", "*.pyc", ".ruff_cache"),
    )


def _marker_events(marker: Path, token: str) -> list[dict]:
    try:
        lines = marker.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (
            isinstance(event, dict)
            and event.get("token") == token
            and event.get("event") == "reached"
            and isinstance(event.get("detail"), str)
            and isinstance(event.get("test", ""), str)
        ):
            events.append(event)
    return events


def _probe(
    source_root: Path,
    tests: str,
    base: Path,
    decisions: tuple[Decision, ...],
    timeout: float,
    driver: Path,
) -> tuple[_Probe, float]:
    base.mkdir()
    root = base / "copy"
    _copy(source_root, root)
    marker = base / "marker"
    token = "probe"
    groups: dict[str, list[Decision]] = {}
    for decision in decisions:
        groups.setdefault(decision.module, []).append(decision)
    for module, group in groups.items():
        source = (root / module).read_text(encoding="utf-8")
        (root / module).write_text(
            _instrument(source, marker, token, tuple(group)), encoding="utf-8"
        )
    started = time.monotonic()
    status, result, detail = _run_suite(root, tests, base, timeout, driver)
    elapsed = time.monotonic() - started
    if status != "passed":
        return _Probe({}, frozenset(), (), f"suite {status}: {detail}"), elapsed
    return _probe_hits(_marker_events(marker, token), decisions, result["ids"]), elapsed


def _probe_hits(
    events: list[dict], decisions: tuple[Decision, ...], ordered_ids: list[str]
) -> _Probe:
    names = {decision.name for decision in decisions}
    selections: dict[str, list[str]] = {decision.name: [] for decision in decisions}
    seen = {decision.name: set() for decision in decisions}
    unattributed: set[str] = set()
    for event in events:
        name = event["detail"]
        if name not in names:
            continue
        test = event.get("test") or "unattributed"
        if test == "unattributed":
            unattributed.add(name)
        elif test not in seen[name]:
            seen[name].add(test)
            selections[name].append(test)
    order = {test: index for index, test in enumerate(ordered_ids)}
    return _Probe(
        {
            name: tuple(sorted(ids, key=lambda test: order.get(test, len(order))))
            for name, ids in selections.items()
        },
        frozenset(unattributed),
        tuple(ordered_ids),
        None,
    )


def _selected_label(count: int) -> str:
    return f"{count} selected test" + ("" if count == 1 else "s")


def _fresh_copy(
    source_root: Path, base: Path, item: tuple[Decision, str] | None = None
) -> Path:
    base.mkdir()
    root = base / "copy"
    _copy(source_root, root)
    if item is not None:
        decision, mutated = item
        (root / decision.module).write_text(mutated, encoding="utf-8")
    return root


def _import_check(root: Path, module: str, timeout: float) -> str | None:
    dotted = Path(module).with_suffix("").as_posix().replace("/", ".")
    code = f"import sys; sys.path.insert(0, {str(root)!r}); import {dotted}"
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"module {dotted} import exceeded {timeout:g} seconds"
    except OSError as error:
        return f"cannot import module {dotted}: {error}"
    if completed.returncode != 0:
        return f"module {dotted} failed to import: {completed.stderr.strip()[-5000:]}"
    return None


def _nonpassing_ids(order: list[str], result: dict) -> list[str]:
    failed = set(result["failures"]) | set(result["errors"]) | set(result["unexpected_successes"])
    return [
        test
        for test in order
        if any(item == test or item.startswith(test + " ") for item in failed)
    ]


def _stable(
    decision: Decision,
    source_root: Path,
    tests: str,
    base: Path,
    nonpassing: list[str],
    timeout: float,
    driver: Path,
    label: str,
) -> Outcome:
    state = base / "stable"
    root = _fresh_copy(source_root, state)
    status, _result, detail = _run_suite(
        root, tests, state, timeout, driver, selected=tuple(nonpassing), failfast=True
    )
    if status == "failed":
        return Outcome(
            decision.name,
            "unstable",
            f"{label}: {', '.join(nonpassing)} failed unmutated",
        )
    if status != "passed":
        return Outcome(decision.name, status, f"{label}: unstable check {status}: {detail}")
    return Outcome(decision.name, "killed", f"{label}: {', '.join(nonpassing)}")


def _targeted(
    decision: Decision,
    source_root: Path,
    tests: str,
    base: Path,
    root: Path,
    selection: tuple[str, ...],
    timeout: float,
    driver: Path,
) -> Outcome:
    label = _selected_label(len(selection))
    work = base / "selected"
    work.mkdir()
    status, result, detail = _run_suite(
        root, tests, work, timeout, driver, selected=selection, failfast=True
    )
    if status in ("error", "timed out"):
        return Outcome(decision.name, status, f"{label}: {detail}")
    ids = result["ids"]
    if ids != list(selection[: len(ids)]):
        return Outcome(
            decision.name, "error", f"{label}: did not execute the selected tests in order"
        )
    if status == "passed":
        if ids != list(selection):
            return Outcome(
                decision.name, "error", f"{label}: did not execute every selected test"
            )
        return Outcome(decision.name, "survived", f"{label}: the selected tests passed")
    nonpassing = _nonpassing_ids(list(selection), result)
    if not nonpassing:
        return Outcome(decision.name, "error", f"{label}: {detail}")
    return _stable(decision, source_root, tests, base, nonpassing, timeout, driver, label)


def _full(
    decision: Decision,
    source_root: Path,
    tests: str,
    base: Path,
    root: Path,
    baseline_ids: list[str],
    timeout: float,
    driver: Path,
) -> Outcome:
    label = "full suite (unattributed hits)"
    work = base / "full"
    work.mkdir()
    status, result, detail = _run_suite(root, tests, work, timeout, driver)
    if status in ("error", "timed out"):
        return Outcome(decision.name, status, f"{label}: {detail}")
    if result["ids"] != baseline_ids:
        return Outcome(
            decision.name,
            "error",
            f"{label}: mutant did not run the same tests as the probe",
        )
    if status == "passed":
        return Outcome(
            decision.name, "survived", f"{label}: the suite passed with the mutation"
        )
    nonpassing = _nonpassing_ids(baseline_ids, result)
    if not nonpassing:
        return Outcome(decision.name, "error", f"{label}: {detail}")
    return _stable(decision, source_root, tests, base, nonpassing, timeout, driver, label)


def _one(
    source_root: Path,
    tests: str,
    base: Path,
    item: tuple[Decision, str],
    timeout: float,
    baseline_ids: list[str],
    driver: Path,
    probe: _Probe,
) -> Outcome:
    decision, _mutated = item
    try:
        root = _fresh_copy(source_root, base, item)
        invalid = _import_check(root, decision.module, timeout)
        if invalid is not None:
            return Outcome(decision.name, "invalid", invalid)
        if decision.name in probe.unattributed:
            return _full(
                decision, source_root, tests, base, root, baseline_ids, timeout, driver
            )
        selection = probe.selections.get(decision.name, ())
        if not selection:
            return Outcome(decision.name, "survived", "no test reached its target")
        return _targeted(
            decision, source_root, tests, base, root, selection, timeout, driver
        )
    except Exception as error:
        return Outcome(decision.name, "error", f"mutation setup failed: {type(error).__name__}: {error}")


def run_mutations(
    source_root: Path,
    decisions: tuple[Decision, ...],
    *,
    tests: str = "tests",
    timeout: float = 900,
    workers: int = 2,
) -> Report:
    source_root = source_root.resolve()
    started = time.monotonic()
    probe_seconds = 0.0
    if timeout <= 0 or workers < 1:
        return Report(
            (),
            ("timeout and worker count must be positive",),
            0.0,
            time.monotonic() - started,
        )
    try:
        with tempfile.TemporaryDirectory(prefix="qg-mutation-") as temporary:
            work = Path(temporary)
            pristine = work / "pristine"
            _copy(source_root, pristine)
            prepared = _prepare(pristine, decisions)
            driver = work / "suite_driver.py"
            original_driver = Path(__file__).resolve()
            if original_driver.is_relative_to(source_root):
                original_driver = pristine / original_driver.relative_to(source_root)
            shutil.copyfile(original_driver, driver)
            probe, probe_seconds = _probe(
                pristine, tests, work / "probe", decisions, timeout, driver
            )
            if probe.failure is not None:
                return Report(
                    (),
                    (f"probe {probe.failure}",),
                    probe_seconds,
                    time.monotonic() - started,
                )
            reached = sum(bool(selection) for selection in probe.selections.values())
            print(
                f"probe: {reached} / {len(decisions)} targets reached in {probe_seconds:.1f} s",
                flush=True,
            )

            def execute(pair):
                index, item = pair
                return _one(
                    pristine,
                    tests,
                    work / f"mutant-{index:03d}",
                    item,
                    timeout,
                    list(probe.ids),
                    driver,
                    probe,
                )

            with ThreadPoolExecutor(max_workers=workers) as executor:
                outcomes = []
                for outcome in executor.map(execute, enumerate(prepared)):
                    print(f"{outcome.name}: {outcome.status}: {outcome.detail}", flush=True)
                    outcomes.append(outcome)
            return Report(
                tuple(outcomes), (), probe_seconds, time.monotonic() - started
            )
    except Exception as error:
        return Report(
            (),
            (f"mutation setup failed: {type(error).__name__}: {error}",),
            probe_seconds,
            time.monotonic() - started,
        )


def main() -> int:
    if len(sys.argv) >= 5 and sys.argv[1] == "--suite":
        selected = None
        failfast = False
        options = sys.argv[5:]
        while options:
            option = options.pop(0)
            if option == "--selected" and options:
                selected = json.loads(Path(options.pop(0)).read_text(encoding="utf-8"))
            elif option == "--failfast":
                failfast = True
            else:
                print("usage: python3 -I tests/mutate_gate.py", file=sys.stderr)
                return 2
        return _suite(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), selected, failfast)
    if len(sys.argv) != 1:
        print("usage: python3 -I tests/mutate_gate.py", file=sys.stderr)
        return 2
    report = run_mutations(Path(__file__).resolve().parent.parent, DECISIONS)
    for error in report.errors:
        print(f"mutation: {error}", file=sys.stderr)
    print(
        f"mutation: {sum(item.status == 'killed' for item in report.outcomes)} / "
        f"{len(report.outcomes)} killed; probe {report.probe_seconds:.1f} s; "
        f"total {report.total_seconds:.1f} s",
        flush=True,
    )
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
