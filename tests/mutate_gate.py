#!/usr/bin/env python3
"""Run a fixed set of decision mutations against isolated copies of the gate."""

from __future__ import annotations

import ast
import copy
import hashlib
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
        "decision",
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
        "trust_gitlink_head",
        "quality_gate/trust.py",
        "_gitlink_changed",
        "comparison",
        "candidate.head != candidate.commit",
        "A checked-out protected gitlink must match its index commit.",
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
        "trust_graft",
        "quality_gate/trust.py",
        "_refuse_graft",
        "remove_raise",
        'raise UsageError(\n            f"{graft}: --policy-from: expected no graft file in the "\n'
        '            "candidate repository, got a graft that can rewrite the "\n'
        '            "trusted history"\n        )',
        "Candidate grafts cannot rewrite trusted history.",
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
        "trust_prune_identity",
        "quality_gate/trust.py",
        "_allowed_change",
        "comparison",
        'new_entry.get("candidate_sha256") == _sha256(written)',
        "A prune may change only the exact bytes written by the gate.",
    ),
    Decision(
        "trust_identity_comparison",
        "quality_gate/trust.py",
        "_section_problems",
        "comparison",
        "old.get(name) != new.get(name)",
        "Changes to a gate file or tool payload are errors.",
    ),
    Decision(
        "owners_owner_boundary",
        "quality_gate/owners.py",
        "_file_findings",
        "comparison",
        "relative in rule.owners",
        "Only declared owner files are exempt from violations.",
    ),
    Decision(
        "owners_allow_scope",
        "quality_gate/owners.py",
        "_uncovered",
        "negate",
        "not any(covered(hit, exemption) for exemption in allowed)",
        "Only a matching allow covering an occurrence exempts it.",
    ),
    Decision(
        "owners_missing_owner",
        "quality_gate/owners.py",
        "_check_stale",
        "remove_raise",
        'raise ConfigError(\n'
        '                f"owners: rule {rule.name}: owner file {owner} '
        'is missing or not an enumerated regular file"\n'
        '            )',
        "A missing or non-regular owner is a configuration error.",
    ),
    Decision(
        "owners_text_allow_boundary",
        "quality_gate/owners_match.py",
        "covered",
        "comparison",
        "allowed.start <= forbidden.start",
        "A text allow may start exactly at the forbidden match.",
    ),
    Decision(
        "owner_match_verdict",
        "quality_gate/owners_match.py",
        "covered",
        "opposite_return",
        "return False",
        "An occurrence outside the allow scope remains forbidden.",
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
    source: str, marker: Path, token: str, reached: tuple[Decision, ...] = ()
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
    if reached:
        source = _insert_reached(source, reached)
    lines = source.splitlines(keepends=True)
    # Existing and future TestResult subclasses may override callbacks without
    # delegating to the base class, so instrument each implementation.
    preamble = (
        "\n"
        "import json as _qg_mutation_json, os as _qg_mutation_os, sys as _qg_mutation_sys, "
        "traceback as _qg_mutation_traceback, unittest as _qg_mutation_unittest\n"
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
        "_qg_mutation_record('loaded')\n"
        "def _qg_mutation_hook(exc_type, exc, tb):\n"
        "    detail = ''.join(_qg_mutation_traceback.format_exception(exc_type, exc, tb))\n"
        "    _qg_mutation_record('failure', detail)\n"
        "    _qg_mutation_sys.__excepthook__(exc_type, exc, tb)\n"
        "_qg_mutation_sys.excepthook = _qg_mutation_hook\n"
        "def _qg_mutation_test_error(error):\n"
        "    detail = ''.join(_qg_mutation_traceback.format_exception(*error))\n"
        "    _qg_mutation_record('error', detail)\n"
        "def _qg_mutation_wrap_error(original):\n"
        "    def add_error(self, test, error):\n"
        "        _qg_mutation_test_error(error)\n"
        "        return original(self, test, error)\n"
        "    return add_error\n"
        "def _qg_mutation_wrap_subtest(original):\n"
        "    def add_subtest(self, test, subtest, error):\n"
        "        if error is not None and not issubclass(error[0], test.failureException):\n"
        "            _qg_mutation_test_error(error)\n"
        "        return original(self, test, subtest, error)\n"
        "    return add_subtest\n"
        "def _qg_mutation_wrap_result(result):\n"
        "    if 'addError' in result.__dict__:\n"
        "        result.addError = _qg_mutation_wrap_error(result.addError)\n"
        "    if 'addSubTest' in result.__dict__:\n"
        "        result.addSubTest = _qg_mutation_wrap_subtest(result.addSubTest)\n"
        "    for child in result.__subclasses__():\n"
        "        _qg_mutation_wrap_result(child)\n"
        "def _qg_mutation_subclass_hook(previous):\n"
        "    def init_subclass(cls, **kwargs):\n"
        "        if previous is None:\n"
        "            super(_qg_mutation_unittest.TestResult, cls).__init_subclass__(**kwargs)\n"
        "        else:\n"
        "            previous.__get__(None, cls)(**kwargs)\n"
        "        _qg_mutation_wrap_result(cls)\n"
        "    return classmethod(init_subclass)\n"
        "_qg_mutation_wrap_result(_qg_mutation_unittest.TestResult)\n"
        "_qg_mutation_unittest.TestResult.__init_subclass__ = _qg_mutation_subclass_hook(\n"
        "    _qg_mutation_unittest.TestResult.__dict__.get('__init_subclass__'))\n"
    )
    trailer = "\n_qg_mutation_record('imported')\n"
    return "".join(lines[:prefix]) + preamble + "".join(lines[prefix:]) + trailer


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
        self.fixture_failures: list[str] = []
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

    def addFailure(self, test, error):
        fixture_frames = {
            "_callSetUp", "_callTearDown", "_callCleanup", "setUpClass", "tearDownClass",
            "setUpModule", "tearDownModule", "doClassCleanups", "doModuleCleanups",
        }
        trace = error[2]
        while trace is not None:
            if trace.tb_frame.f_code.co_name in fixture_frames:
                self.fixture_failures.append(test.id())
                break
            trace = trace.tb_next
        super().addFailure(test, error)


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
        "fixture_failures": result.fixture_failures,
        "errors": [f"{test.id()}: {trace[-5000:]}" for test, trace in result.errors],
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
        if key != "QG_PYTHON" and not key.startswith("COVERAGE_")
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
            "fixture_failures",
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
    if result["errors"]:
        return "error", result, "test execution, setup, or import error: " + "\n".join(result["errors"][:3])
    if result["fixture_failures"]:
        return "error", result, "test setup or cleanup failure: " + ", ".join(result["fixture_failures"][:3])
    if result["skipped"] or result["expected_failures"] or result["unexpected_successes"]:
        return "error", result, "suite has skipped, expected-failure, or unexpected-success tests"
    if not result["ids"]:
        return "error", result, "suite ran zero tests"
    return ("failed" if result["failures"] else "passed"), result, tail


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
            and event.get("event") in ("loaded", "imported", "failure", "error", "reached")
            and isinstance(event.get("detail"), str)
            and isinstance(event.get("test", ""), str)
        ):
            events.append(event)
    return events


def _marker_failure(events: list[dict]) -> str | None:
    failures = [event["detail"] for event in events if event["event"] in ("failure", "error")]
    return failures[-1][-5000:] if failures else None


def _probe(
    source_root: Path,
    tests: str,
    base: Path,
    decisions: tuple[Decision, ...],
    timeout: float,
    driver: Path,
    ordered_ids: list[str],
) -> tuple[_Probe, float]:
    base.mkdir()
    root = base / "copy"
    _copy(source_root, root)
    marker = base / "loaded"
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
    status, _result, detail = _run_suite(root, tests, base, timeout, driver)
    elapsed = time.monotonic() - started
    if status != "passed":
        return _Probe({}, frozenset(), f"suite {status}: {detail}"), elapsed
    return _probe_hits(_marker_events(marker, token), decisions, ordered_ids), elapsed


def _probe_hits(
    events: list[dict], decisions: tuple[Decision, ...], ordered_ids: list[str]
) -> _Probe:
    names = {decision.name for decision in decisions}
    selections: dict[str, list[str]] = {decision.name: [] for decision in decisions}
    seen = {decision.name: set() for decision in decisions}
    unattributed: set[str] = set()
    for event in events:
        if event["event"] != "reached":
            continue
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
        None,
    )


def _selection_choice(
    decision: Decision, probe: _Probe, failures: dict[tuple[str, ...], str | None]
) -> tuple[tuple[str, ...], str | None]:
    if probe.failure is not None:
        return (), f"probe did not pass ({probe.failure})"
    if decision.name in probe.unattributed:
        return (), "unattributed hits"
    selection = probe.selections.get(decision.name, ())
    if not selection:
        return (), "no test reached"
    return (selection, None) if failures.get(selection) is None else ((), failures[selection])


def _selection_failures(
    source_root: Path,
    tests: str,
    work: Path,
    selections: set[tuple[str, ...]],
    timeout: float,
    driver: Path,
    workers: int,
) -> dict[tuple[str, ...], str | None]:
    distinct = sorted(selections)
    if not distinct:
        return {}

    def check(pair: tuple[int, tuple[str, ...]]) -> str | None:
        index, selection = pair
        base = work / f"selection-{index:03d}"
        try:
            base.mkdir()
            root = base / "copy"
            _copy(source_root, root)
            status, result, _detail = _run_suite(
                root, tests, base, timeout, driver, selected=selection, failfast=True
            )
            if status == "passed" and result["ids"] == list(selection):
                return None
            return f"selection failed unmutated ({status})"
        except Exception as error:
            return f"selection failed unmutated ({type(error).__name__}: {error})"

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(check, enumerate(distinct)))
    return dict(zip(distinct, results, strict=True))


def _selected_label(count: int) -> str:
    return f"{count} selected test" + ("" if count == 1 else "s")


def _mutant_copy(
    source_root: Path, base: Path, item: tuple[Decision, str]
) -> tuple[Decision, Path, Path, str]:
    decision, mutated = item
    base.mkdir()
    root = base / "copy"
    _copy(source_root, root)
    marker = base / "loaded"
    token = decision.name + ":" + hashlib.sha256(mutated.encode("utf-8")).hexdigest()
    (root / decision.module).write_text(_instrument(mutated, marker, token), encoding="utf-8")
    return decision, root, marker, token


def _targeted(
    source_root: Path,
    tests: str,
    base: Path,
    item: tuple[Decision, str],
    timeout: float,
    driver: Path,
    selection: tuple[str, ...],
) -> Outcome | str:
    decision, root, marker, token = _mutant_copy(source_root, base, item)
    status, result, _detail = _run_suite(
        root, tests, base, timeout, driver, selected=selection, failfast=True
    )
    events = _marker_events(marker, token)
    failure = _marker_failure(events)
    if failure is not None:
        return "selected run recorded an import or execution failure"
    if status in ("error", "timed out"):
        return f"selected run {status}"
    if not any(event["event"] == "loaded" for event in events):
        return "selected run did not load the mutant"
    if not any(event["event"] == "imported" for event in events):
        return "selected run did not complete the mutant import"
    ids = result["ids"]
    if ids != list(selection[: len(ids)]):
        return "selected run did not execute the selected tests in order"
    if status == "failed":
        if not ids:
            return "selected run recorded no executed test"
        return Outcome(
            decision.name,
            "killed",
            f"{_selected_label(len(selection))}: {', '.join(result['failures'][:3])}",
        )
    if ids != list(selection):
        return "selected run did not execute every selected test"
    return "selected tests passed"


def _full(
    source_root: Path,
    tests: str,
    base: Path,
    item: tuple[Decision, str],
    timeout: float,
    baseline_ids: list[str],
    driver: Path,
    reason: str,
) -> Outcome:
    decision, root, marker, token = _mutant_copy(source_root, base, item)
    status, result, detail = _run_suite(root, tests, base, timeout, driver)
    events = _marker_events(marker, token)
    failure = _marker_failure(events)
    prefix = f"full suite: {reason}"
    if failure is not None:
        return Outcome(decision.name, "error", prefix + ": mutant import or execution failure: " + failure)
    if status in ("error", "timed out"):
        return Outcome(decision.name, status, f"{prefix}: {detail}")
    if not any(event["event"] == "loaded" for event in events):
        return Outcome(
            decision.name,
            "error",
            prefix + ": mutated module was not shown to be loaded by the suite",
        )
    if not any(event["event"] == "imported" for event in events):
        return Outcome(decision.name, "error", prefix + ": mutated module did not complete import")
    if result["ids"] != baseline_ids:
        return Outcome(
            decision.name, "error", prefix + ": mutant did not run the same tests as the passing suite"
        )
    if status == "failed":
        return Outcome(decision.name, "killed", f"{prefix}: {', '.join(result['failures'][:3])}")
    return Outcome(decision.name, "survived", prefix + ": the suite passed with the mutation")


def _one(
    source_root: Path,
    tests: str,
    base: Path,
    item: tuple[Decision, str],
    timeout: float,
    baseline_ids: list[str],
    driver: Path,
    probe: _Probe,
    selection_failures: dict[tuple[str, ...], str | None],
) -> Outcome:
    decision, _mutated = item
    try:
        base.mkdir()
        selection, reason = _selection_choice(decision, probe, selection_failures)
        if reason is None:
            targeted = _targeted(
                source_root, tests, base / "selected", item, timeout, driver, selection
            )
            if isinstance(targeted, Outcome):
                return targeted
            reason = targeted
        return _full(
            source_root,
            tests,
            base / "full",
            item,
            timeout,
            baseline_ids,
            driver,
            reason,
        )
    except Exception as error:
        return Outcome(decision.name, "error", f"mutation setup failed: {type(error).__name__}: {error}")


def run_mutations(
    source_root: Path,
    decisions: tuple[Decision, ...],
    *,
    tests: str = "tests",
    timeout: float = 900,
    workers: int = 4,
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
            baseline = work / "baseline"
            baseline.mkdir()
            _copy(pristine, baseline / "copy")
            status, result, detail = _run_suite(baseline / "copy", tests, baseline, timeout, driver)
            if status != "passed":
                return Report(
                    (),
                    (f"unmutated suite {status}: {detail}",),
                    0.0,
                    time.monotonic() - started,
                )
            print(f"unmutated suite: passed ({len(result['ids'])} tests)", flush=True)

            probe, probe_seconds = _probe(
                pristine, tests, work / "probe", decisions, timeout, driver, result["ids"]
            )
            if probe.failure is not None:
                print(f"probe: {probe.failure}; every mutant runs the full suite", flush=True)
            else:
                reached = sum(bool(selection) for selection in probe.selections.values())
                print(
                    f"probe: {reached} / {len(decisions)} targets reached in {probe_seconds:.1f} s",
                    flush=True,
                )
            candidates = set()
            for decision in decisions:
                selection, reason = _selection_choice(decision, probe, {})
                if reason is None:
                    candidates.add(selection)
            selections = _selection_failures(
                pristine, tests, work, candidates, timeout, driver, workers
            )

            def execute(pair):
                index, item = pair
                return _one(
                    pristine,
                    tests,
                    work / f"mutant-{index:03d}",
                    item,
                    timeout,
                    result["ids"],
                    driver,
                    probe,
                    selections,
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
