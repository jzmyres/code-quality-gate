"""Run Python tests under coverage and collect their counts and evidence."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import output_patterns, policy
from .coverage_tool import (
    combine_coverage,
    coverage_config_path,
    coverage_config_text,
    registry_dir,
    write_coverage_config,
)
from .policy import (
    CheckDef,
    DEFAULT_TESTS_BUDGET_SECONDS,
    GateError,
    UnsupportedError,
    UsageError,
    _config_error,
    _integer,
)
from .runner import Diagnostics, RunResult, execution_outcome, mark_step, run
from .tools import installed_tool


if TYPE_CHECKING:
    from .adapters import ParsedSpec


_DISCOVER_SCRIPT = """\
import json
import sys
import unittest
from unittest.main import TestProgram


class _Collector:
    def run(self, suite):
        found = []

        def walk(test):
            if isinstance(test, unittest.TestSuite):
                for child in test:
                    walk(child)
            else:
                found.append(test.id())

        walk(suite)
        with open(sys.argv[1], "w", encoding="utf-8") as stream:
            json.dump(found, stream)
        return unittest.TestResult()


TestProgram(
    module=None,
    argv=["qg-discover", "discover", *sys.argv[2:]],
    testRunner=_Collector(),
    exit=False,
)
"""

_WORKER_RESULT = re.compile(
    r"^(.+?) \(([^()]+)\)(?: \.\.\.|$)", re.MULTILINE
)
_WORKER_FAILURE = re.compile(
    r"^(FAIL|ERROR): .*?\(([^()]+)\)", re.MULTILINE
)

_COORDINATOR_SCRIPT = """\
import json
import subprocess
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = json.load(stream)
results = {}
processes = []
for worker in manifest:
    stdout = open(worker["stdout"], "wb")
    stderr = open(worker["stderr"], "wb")
    process = subprocess.Popen(
        worker["command"], stdout=stdout, stderr=stderr
    )
    processes.append((worker["index"], process, stdout, stderr))
for index, process, stdout, stderr in processes:
    results[str(index)] = process.wait()
    stdout.close()
    stderr.close()
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(results, stream)
"""


@dataclass(frozen=True)
class PythonTestsSpec:
    run: tuple[str, ...]
    tests_pattern: str
    tests_pattern_re: re.Pattern[str]
    skipped_pattern: str | None
    skipped_pattern_re: re.Pattern[str] | None
    budget_seconds: int
    workers: int = 1


def _python_tests_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .adapters import ParsedSpec

    spec = _parse_python_tests(raw, path, full_key)
    return ParsedSpec(spec, "test-count/1", ("tests",))


def _parse_python_tests(
    raw: dict[str, Any], path: Path, full_key: str
) -> PythonTestsSpec:
    run = policy._argv_list(raw, "run", path, f"{full_key}.run")
    if not run:
        raise _config_error(
            path, f"{full_key}.run", "a non-empty argument list", "an empty list"
        )
    pattern_text, pattern, skipped_pattern_text, skipped_pattern = output_patterns._test_patterns(
        raw, path, full_key
    )
    if pattern is None:
        raise _config_error(
            path,
            f"{full_key}.tests_pattern",
            "a regular expression with one capture group",
            "missing",
        )
    budget = _integer(
        raw,
        "budget_seconds",
        path,
        f"{full_key}.budget_seconds",
        default=DEFAULT_TESTS_BUDGET_SECONDS,
        minimum=1,
    )
    workers = _integer(
        raw,
        "workers",
        path,
        f"{full_key}.workers",
        default=1,
        minimum=1,
    )
    if workers > 1 and tuple(run[:4]) != (
        "{python}", "-m", "unittest", "discover",
    ):
        raise _config_error(
            path,
            f"{full_key}.workers",
            "a {python} -m unittest discover run for workers above 1",
            repr(tuple(run)),
        )
    return PythonTestsSpec(
        tuple(run),
        pattern_text,
        pattern,
        skipped_pattern_text,
        skipped_pattern,
        budget,
        workers,
    )


def coverage_prefix_values(root: Path, data_dir: Path) -> list[str]:
    """The coverage command and QG_PYTHON value before creating its files."""
    tool, installation = installed_tool("coverage")
    runner = Path(__file__).with_name("covrun.py")
    return [
        sys.executable,
        "-I",
        str(runner),
        str(data_dir),
        str(root),
        str(installation),
        tool.version,
        tool.payload_sha256,
        str(coverage_config_path(data_dir)),
        str(registry_dir(data_dir)),
    ]


def coverage_prefix(root: Path, data_dir: Path) -> list[str]:
    """The in-place expansion of {python} and the value exported as QG_PYTHON."""
    write_coverage_config(data_dir, root)
    return coverage_prefix_values(root, data_dir)


def expand_run(run: tuple[str, ...], prefix: list[str]) -> list[str]:
    expanded: list[str] = []
    for argument in run:
        if argument == "{python}":
            expanded.extend(prefix)
        else:
            expanded.append(argument)
    return expanded


def _executed_tests(
    ran: int | None, skipped: int | None
) -> int | None:
    if ran is None or skipped is None:
        return None
    return ran - skipped


def _tests_summary(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    combined: str,
    diagnostics: Diagnostics,
    deadline: float,
) -> tuple[
    int | None, int | None, str | None, Any | None
]:
    from .checks import _tests_result

    matches, evaluation = output_patterns._pattern_matches(
        output_patterns._command_patterns(spec),
        combined,
        max(0.0, deadline - time.monotonic()),
    )
    if matches is None:
        if evaluation is not None and evaluation.execution == "budget":
            reason = "test summary matching exceeded the remaining budget"
            return (
                None,
                None,
                reason,
                _tests_result(
                    check,
                    spec,
                    start,
                    prefix,
                    reason,
                    execution="budget",
                    diagnostics=diagnostics,
                    report=False,
                ),
            )
        reason = "test summary matching failed"
        return (
            None,
            None,
            reason,
            _tests_result(
                check,
                spec,
                start,
                prefix,
                reason,
                outcome="error",
                execution="error",
                diagnostics=diagnostics,
                report=False,
            ),
        )
    mark_step("test count analysis")
    ran, skipped, error = output_patterns.summarize_matches(
        spec, matches.get("tests", []), matches.get("skipped", []),
    )
    return ran, skipped, error, None


def _tests_failure_reason(
    run_result: RunResult,
    ran: int | None,
    skipped: int | None,
    executed: int | None,
) -> str:
    if executed == 0:
        return (
            f"command exited {run_result.returncode} and no test executed: "
            f"{ran} ran, {skipped} skipped; zero tests is not a pass"
        )
    return f"command exited {run_result.returncode}"


def _tests_failed(
    check: CheckDef,
    spec: Any,
    run_result: RunResult,
    diagnostics: Diagnostics,
    combined: str,
    prefix: str,
    start: float,
    deadline: float,
) -> Any:
    from .checks import _tests_result

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline,
    )
    if failure is not None:
        return failure
    if count_error is not None and "ambiguous test summary" in count_error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            count_error,
            outcome="unsupported",
            diagnostics=diagnostics,
            report=False,
        )
    executed = _executed_tests(ran, skipped)
    return _tests_result(
        check,
        spec,
        start,
        prefix,
        _tests_failure_reason(run_result, ran, skipped, executed),
        diagnostics=diagnostics,
        measurement={"tests": executed} if executed is not None else None,
        tests_ran=ran,
        tests_skipped=skipped,
        report=False,
    )


def _test_environment(python_prefix: list[str]) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("COVERAGE_") and name != "COVERAGE_CORE":
            del environment[name]
    environment["QG_PYTHON"] = json.dumps(python_prefix)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _combine_tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    settings: str,
    data_dir: Path,
    combined_file: Path,
    diagnostics: Diagnostics,
) -> Any | None:
    from .checks import _tests_result

    try:
        mark_step("coverage combination")
        combine_coverage(data_dir, combined_file, settings)
    except (UnsupportedError, GateError) as error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"coverage combination failed: {error}",
            outcome="unsupported",
            diagnostics=diagnostics,
        )
    return None


def _tests_setup(
    root: Path,
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    evidence_dir: Path,
) -> tuple[Path, list[str]] | Any:
    from .checks import _tests_result

    data_dir = evidence_dir / "data"
    try:
        data_dir.mkdir()
        mark_step("coverage setup")
        python_prefix = coverage_prefix(root, data_dir)
    except UnsupportedError as error:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            str(error),
            outcome="unsupported",
            execution="error",
            diagnostics=Diagnostics(error=str(error)),
        )
    except UsageError as error:
        return _tests_result(
            check, spec, start, prefix, str(error),
            outcome="error", execution="error",
            diagnostics=Diagnostics(error=str(error)),
            configuration_error=True,
        )
    except OSError as error:
        message = f"cannot create coverage data directory: {error}"
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            message,
            outcome="error",
            execution="error",
            diagnostics=Diagnostics(error=message),
        )
    return data_dir, python_prefix


def _tests_execution_failure(
    check: CheckDef,
    spec: Any,
    run_result: RunResult,
    diagnostics: Diagnostics,
    combined: str,
    prefix: str,
    start: float,
) -> Any | None:
    from .checks import _tests_result

    outcome = execution_outcome(run_result.execution)
    if outcome.error:
        reason = run_result.error or "cannot run command"
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            reason,
            outcome="error",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
        )
    if outcome.budget:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command exceeded its {spec.budget_seconds} second budget",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
        )
    if outcome.signal:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            f"command terminated by signal {-run_result.returncode}",
            execution=outcome.name,
            diagnostics=diagnostics,
            report=False,
        )
    return None


def _tests_counts(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    combined: str,
    diagnostics: Diagnostics,
    deadline: float,
) -> tuple[tuple[int, int, int] | None, Any | None]:
    from .checks import _tests_result

    ran, skipped, count_error, failure = _tests_summary(
        check, spec, start, prefix, combined, diagnostics, deadline,
    )
    if failure is not None:
        return None, failure
    if count_error is not None:
        return None, _tests_result(
            check,
            spec,
            start,
            prefix,
            count_error,
            outcome="unsupported",
            diagnostics=diagnostics,
            report=False,
        )
    assert ran is not None and skipped is not None
    executed = ran - skipped
    if executed == 0:
        return None, _tests_result(
            check,
            spec,
            start,
            prefix,
            f"no test executed: {ran} ran, {skipped} skipped; "
            "zero tests is not a pass",
            diagnostics=diagnostics,
            measurement={"tests": 0},
            tests_ran=ran,
            tests_skipped=skipped,
            report=False,
        )
    return (ran, skipped, executed), None


def _tests_evidence(
    check: CheckDef,
    spec: Any,
    start: float,
    prefix: str,
    evidence_dir: Path,
    root: Path,
    data_dir: Path,
    ran: int,
    skipped: int,
    executed: int,
    diagnostics: Diagnostics,
) -> Any:
    from .checks import _check_result, _tests_result

    from .coverage_tool import _coverage_config_problem

    settings = coverage_config_text(root)
    mark_step("coverage configuration validation")
    problem = _coverage_config_problem(data_dir, settings)
    if problem is not None:
        return _tests_result(
            check,
            spec,
            start,
            prefix,
            problem,
            outcome="error",
            execution="error",
            diagnostics=Diagnostics(error=problem),
            configuration_error=True,
        )
    combined_file = evidence_dir / "combined" / ".coverage"
    config_file = coverage_config_path(data_dir)
    failure = _combine_tests_evidence(
        check,
        spec,
        start,
        prefix,
        settings,
        data_dir,
        combined_file,
        diagnostics,
    )
    if failure is not None:
        return failure
    outcome = _check_result(
        check,
        start,
        "pass",
        budget_seconds=spec.budget_seconds,
        diagnostics=diagnostics,
        measurement={"tests": executed},
        tests_ran=ran,
        tests_skipped=skipped,
        evidence_path=combined_file,
        adapter_data={"coverage_config": config_file, "coverage_settings": settings},
    )
    print(
        f"{prefix}: passed ({executed} tests, "
        f"{outcome.duration_seconds:.2f}s)",
        flush=True,
    )
    return outcome


def _discover_option(
    run: tuple[str, ...], names: tuple[str, ...], default: str
) -> str:
    """The value a discovery option gives, including --name=value."""
    for index, argument in enumerate(run):
        for name in names:
            if argument == name and index + 1 < len(run):
                return run[index + 1]
            if argument.startswith(name + "="):
                return argument.partition("=")[2]
    return default


def _deal_ids(ids: list[str], workers: int) -> list[list[str]]:
    """DEAL the test ids round-robin, in id order, to WORKERS buckets."""
    buckets: list[list[str]] = [[] for _ in range(workers)]
    for position, identifier in enumerate(sorted(ids)):
        buckets[position % workers].append(identifier)
    return buckets


def _valid_ids(ids: Any) -> bool:
    """Whether IDS is the list of strings the discovery helper writes."""
    return isinstance(ids, list) and all(
        isinstance(identifier, str) for identifier in ids
    )


def _read_discovered(path: Path) -> tuple[list[str] | None, str | None]:
    """The discovered ids in PATH, or why its document is unusable."""
    try:
        ids = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, f"cannot read discovered test ids: {error}"
    if not _valid_ids(ids):
        return None, "discovered test ids are not a list of strings"
    return ids, None


def _discovered_ids(
    root: Path,
    discover_run: tuple[str, ...],
    environment: dict[str, str],
    deadline: float,
    directory: Path,
) -> tuple[list[str] | None, str | None]:
    """Discover every test id once, through a helper that only collects them."""
    script = directory / "discover.py"
    script.write_text(_DISCOVER_SCRIPT, encoding="utf-8")
    result_file = directory / "ids.json"
    command = [
        sys.executable, "-I", "-B", str(script), str(result_file),
        *discover_run[4:],
    ]
    result = run(
        command,
        cwd=root,
        env=environment,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    if result.execution != "completed":
        return None, f"test discovery failed: {result.error or result.execution}"
    if result.returncode != 0:
        return None, (
            "test discovery failed: "
            f"{result.combined_text.strip() or result.returncode}"
        )
    return _read_discovered(result_file)


def _worker_source(top: str, ids: list[str]) -> str:
    """The worker test module that loads IDS from the path TOP."""
    return (
        "import os\n"
        "import sys\n"
        "import unittest\n"
        f"sys.path.insert(0, os.path.abspath({top!r}))\n"
        f"IDS = {ids!r}\n"
        "\n\n"
        "def load_tests(loader, tests, pattern):\n"
        "    suite = unittest.TestSuite()\n"
        "    for name in IDS:\n"
        "        suite.addTests(loader.loadTestsFromName(name))\n"
        "    return suite\n"
    )


def _worker_manifest(
    prefix: list[str], directory: Path, top: str, buckets: list[list[str]]
) -> list[dict[str, Any]]:
    """Write one worker module per non-empty bucket and describe its command."""
    manifest: list[dict[str, Any]] = []
    for index, ids in enumerate(buckets):
        if not ids:
            continue
        name = f"worker_{index}.py"
        (directory / name).write_text(
            _worker_source(top, ids), encoding="utf-8"
        )
        manifest.append({
            "index": index,
            "ids": ids,
            "command": [
                *prefix, "-m", "unittest", "discover",
                "-s", str(directory), "-p", name, "-v",
            ],
            "stdout": str(directory / f"stdout-{index}"),
            "stderr": str(directory / f"stderr-{index}"),
        })
    return manifest


def _executed_ids(text: str) -> list[str]:
    """The test ids a worker's verbose output names as having run."""
    return [
        match.group(2)
        for match in _WORKER_RESULT.finditer(text)
        if not match.group(1).startswith(("FAIL:", "ERROR:"))
    ]


def _failure_end(text: str, matches: list[Any], position: int) -> int:
    """Where one failure block ends, before the next failure or the summary."""
    if position + 1 < len(matches):
        return matches[position + 1].start()
    end = text.find("\nRan ", matches[position].end())
    return len(text) if end < 0 else end


def _condition_line(block: str) -> str:
    """The last meaningful line of one failure block, its condition."""
    lines = [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith(("---", "==="))
    ]
    return lines[-1] if lines else "no condition"


def _worker_failures(text: str) -> list[tuple[str, str]]:
    """Each failing test id in TEXT with the condition that failed it."""
    matches = list(_WORKER_FAILURE.finditer(text))
    return [
        (
            match.group(2),
            _condition_line(
                text[match.end():_failure_end(text, matches, position)]
            ),
        )
        for position, match in enumerate(matches)
    ]


def _one_run_each(ids: list[str], executed: list[str]) -> str | None:
    """Why an id did not run exactly once, or None when every id did."""
    discovered = Counter(ids)
    counts = Counter(executed)
    for identifier in sorted(discovered):
        if discovered[identifier] != 1 or counts[identifier] != 1:
            return (
                f"discovered test {identifier} ran {counts[identifier]} "
                "times; expected exactly once"
            )
    return None


def _parallel_texts(
    manifest: list[dict[str, Any]],
) -> tuple[dict[str, str], str | None]:
    """Read each worker's combined output, or name the worker that has none."""
    texts = {}
    for worker in manifest:
        index = worker["index"]
        try:
            stdout = Path(worker["stdout"]).read_text(
                encoding="utf-8", errors="replace"
            )
            stderr = Path(worker["stderr"]).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError as error:
            return {}, f"cannot read worker {index} output: {error}"
        texts[str(index)] = stdout + stderr
    return texts, None


def _skipped_count(
    spec: PythonTestsSpec, text: str
) -> tuple[int, str | None]:
    """A worker's skipped count and any ambiguity in its skipped summary."""
    if spec.skipped_pattern_re is None:
        return 0, None
    skips = spec.skipped_pattern_re.findall(text)
    if len(skips) > 1:
        return 0, "has an ambiguous skipped summary"
    return (int(skips[0]) if skips else 0), None


def _worker_count(
    spec: PythonTestsSpec, text: str
) -> tuple[int, int, str | None]:
    """A worker's ran and skipped counts, or why it has no usable summary."""
    matches = spec.tests_pattern_re.findall(text)
    if len(matches) != 1:
        return 0, 0, "without a test summary"
    skipped, problem = _skipped_count(spec, text)
    if problem is not None:
        return 0, 0, problem
    return int(matches[0]), skipped, None


def _parallel_totals(
    spec: PythonTestsSpec,
    manifest: list[dict[str, Any]],
    results: dict[str, Any],
    texts: dict[str, str],
) -> tuple[
    int, int, list[str], list[tuple[str, str]], list[str], str
]:
    """One run's summed counts, executed ids, failures, problems and output."""
    ran = skipped = 0
    executed: list[str] = []
    failures: list[tuple[str, str]] = []
    problems: list[str] = []
    for worker in manifest:
        index = worker["index"]
        text = texts[str(index)]
        count, skip, problem = _worker_count(spec, text)
        if problem is not None:
            problems.append(
                f"worker {index} exited {results.get(str(index))} {problem} "
                f"({', '.join(worker['ids'])})"
            )
            continue
        ran += count
        skipped += skip
        executed.extend(_executed_ids(text))
        failures.extend(_worker_failures(text))
    combined = "\n".join(texts[str(worker["index"])] for worker in manifest)
    return ran, skipped, executed, failures, problems, combined


def _failure_reason(ran: int, failures: list[tuple[str, str]]) -> str:
    """The summed ran count and every failing test's name and condition."""
    details = "; ".join(
        f"{identifier}: {condition}"
        for identifier, condition in failures
    )
    return f"{ran} tests ran; {details}"


def _nonzero_worker(
    manifest: list[dict[str, Any]], results: dict[str, Any]
) -> dict[str, Any] | None:
    """The first worker whose coordinator recorded a nonzero exit."""
    return next(
        (
            worker for worker in manifest
            if results.get(str(worker["index"])) != 0
        ),
        None,
    )


def _parallel_summary(
    context: Any,
    spec: PythonTestsSpec,
    ids: list[str],
    manifest: list[dict[str, Any]],
    results: dict[str, Any],
    texts: dict[str, str],
    start: float,
) -> tuple[Any, str]:
    from .checks import _tests_result

    ran, skipped, executed, failures, problems, combined = _parallel_totals(
        spec, manifest, results, texts
    )
    diagnostics = Diagnostics(output_tail=combined[-4096:])
    if problems:
        return _tests_result(
            context.check, spec, start, context.prefix, "; ".join(problems),
            outcome="error", diagnostics=diagnostics, report=False,
        ), combined
    problem = _one_run_each(ids, executed)
    if problem is not None:
        return _tests_result(
            context.check, spec, start, context.prefix, problem,
            outcome="error", diagnostics=diagnostics, report=False,
        ), combined
    if failures:
        return _tests_result(
            context.check, spec, start, context.prefix,
            _failure_reason(ran, failures),
            outcome="fail", diagnostics=diagnostics,
            measurement={"tests": ran - skipped},
            tests_ran=ran, tests_skipped=skipped, report=False,
        ), combined
    worker = _nonzero_worker(manifest, results)
    if worker is not None:
        return _tests_result(
            context.check, spec, start, context.prefix,
            f"worker {worker['index']} exited "
            f"{results.get(str(worker['index']))} without a failing test",
            outcome="error", diagnostics=diagnostics, report=False,
        ), combined
    return _tests_evidence(
        context.check, spec, start, context.prefix, context.evidence_dir,
        context.root, context.evidence_dir / "data", ran, skipped,
        ran - skipped, diagnostics,
    ), ""


def _read_worker_results(
    path: Path, manifest: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, dict[str, str], str | None]:
    """The coordinator's exit codes and every worker's combined output."""
    try:
        results = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, {}, f"cannot read worker results: {error}"
    texts, text_error = _parallel_texts(manifest)
    if text_error is not None:
        return None, {}, text_error
    return results, texts, None


def _coordinator_failure(
    context: Any, spec: PythonTestsSpec, start: float, result: Any
) -> Any | None:
    """The coordinator's own error result, or None when it finished."""
    from .checks import _tests_result

    if result.execution != "completed":
        reason = result.error or f"worker coordinator ended {result.execution}"
        return _tests_result(
            context.check, spec, start, context.prefix, reason,
            outcome="error", execution=result.execution,
            diagnostics=result.diagnostics(), report=False,
        )
    if result.returncode != 0:
        reason = f"worker coordinator exited {result.returncode}"
        return _tests_result(
            context.check, spec, start, context.prefix, reason,
            outcome="error", execution=result.execution,
            diagnostics=result.diagnostics(), report=False,
        )
    return None


def _run_worker_batch(
    context: Any,
    spec: PythonTestsSpec,
    ids: list[str],
    python_prefix: list[str],
    directory: Path,
    environment: dict[str, str],
    deadline: float,
    start: float,
) -> tuple[
    Any | None, dict[str, Any] | None, dict[str, str], str,
    list[dict[str, Any]],
]:
    """Start the workers once and read their results and combined output."""
    from .checks import Diagnostics, _tests_result

    top = _discover_option(
        spec.run, ("-t", "--top-level-directory"), ""
    ) or _discover_option(spec.run, ("-s", "--start-directory"), ".")
    manifest = _worker_manifest(
        python_prefix, directory, top, _deal_ids(ids, spec.workers)
    )
    manifest_file = directory / "manifest.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    results_file = directory / "results.json"
    coordinator = directory / "coordinate.py"
    coordinator.write_text(_COORDINATOR_SCRIPT, encoding="utf-8")
    result = run(
        [
            sys.executable, "-I", "-B", str(coordinator),
            str(manifest_file), str(results_file),
        ],
        cwd=context.root,
        env=environment,
        budget_seconds=max(0.0, deadline - time.monotonic()),
    )
    combined = result.combined_text
    failure = _coordinator_failure(context, spec, start, result)
    if failure is not None:
        return failure, None, {}, combined, manifest
    results, texts, error = _read_worker_results(results_file, manifest)
    if error is not None:
        return _tests_result(
            context.check, spec, start, context.prefix, error,
            outcome="error", diagnostics=Diagnostics(error=error),
            report=False,
        ), None, {}, combined, manifest
    return None, results, texts, combined, manifest


def _parallel_outcome(
    context: Any,
    spec: PythonTestsSpec,
    python_prefix: list[str],
    data_dir: Path,
    environment: dict[str, str],
    start: float,
) -> tuple[Any, str]:
    from .checks import Diagnostics, _tests_result

    deadline = start + spec.budget_seconds
    directory = context.evidence_dir / "workers"
    directory.mkdir()
    ids, error = _discovered_ids(
        context.root, spec.run, environment, deadline, directory
    )
    if error is not None:
        return _tests_result(
            context.check, spec, start, context.prefix, error,
            outcome="error", execution="error",
            diagnostics=Diagnostics(error=error), report=False,
        ), ""
    assert ids is not None
    if not ids:
        return _tests_result(
            context.check, spec, start, context.prefix,
            "no test discovered; zero tests is not a pass",
            measurement={"tests": 0}, tests_ran=0, tests_skipped=0,
            report=False,
        ), ""
    failure, results, texts, combined, manifest = _run_worker_batch(
        context, spec, ids, python_prefix, directory, environment,
        deadline, start,
    )
    if failure is not None:
        return failure, combined
    assert results is not None
    return _parallel_summary(
        context, spec, ids, manifest, results, texts, start
    )


def _run_parallel_python_tests(
    context: Any, spec: PythonTestsSpec
) -> Any:
    from .checks import (
        CheckResult,
        _finish_temporary,
        _finish_test_result,
        _temporary_reason,
        _temporary_test_directory,
    )

    root, check, prefix = context.root, context.check, context.prefix
    start = time.monotonic()
    evidence_dir = context.evidence_dir
    setup = _tests_setup(root, check, spec, start, prefix, evidence_dir)
    if isinstance(setup, CheckResult):
        return setup
    data_dir, python_prefix = setup
    environment = _test_environment(python_prefix)
    temporary = _temporary_test_directory()
    environment["TMPDIR"] = str(temporary)
    try:
        result, combined = _parallel_outcome(
            context, spec, python_prefix, data_dir, environment, start
        )
    finally:
        temporary_paths = _finish_temporary(temporary)
    temporary_reason = _temporary_reason(temporary_paths)
    return _finish_test_result(
        result, temporary_reason, context.prefix, combined
    )


def _run_python_tests(context: Any) -> Any:
    """Run the one suite, or its parallel workers when the policy asks."""
    spec = context.check.spec
    if spec.workers > 1:
        return _run_parallel_python_tests(context, spec)
    return _run_single_python_tests(context)


def _run_single_python_tests(context: Any) -> Any:
    from .checks import (
        CheckResult,
        _finish_temporary,
        _finish_test_result,
        _temporary_reason,
        _temporary_test_directory,
        _tests_result,
    )

    root, check, prefix = context.root, context.check, context.prefix
    spec = check.spec
    start = time.monotonic()
    deadline = start + spec.budget_seconds
    evidence_dir = context.evidence_dir
    setup = _tests_setup(root, check, spec, start, prefix, evidence_dir)
    if isinstance(setup, CheckResult):
        return setup
    data_dir, python_prefix = setup

    command = expand_run(spec.run, python_prefix)
    environment = _test_environment(python_prefix)
    temporary = _temporary_test_directory()
    environment["TMPDIR"] = str(temporary)
    mark_step("test command")
    try:
        run_result = run(
            command,
            cwd=root,
            env=environment,
            budget_seconds=max(0.0, deadline - time.monotonic()),
        )
    finally:
        temporary_paths = _finish_temporary(temporary)
    temporary_reason = _temporary_reason(temporary_paths)

    diagnostics = run_result.diagnostics()
    combined = run_result.combined_text
    failure = _tests_execution_failure(
        check, spec, run_result, diagnostics, combined, prefix, start,
    )
    if failure is not None:
        return _finish_test_result(failure, temporary_reason, prefix, combined)
    if run_result.returncode != 0:
        result = _tests_failed(
            check,
            spec,
            run_result,
            diagnostics,
            combined,
            prefix,
            start,
            deadline,
        )
        return _finish_test_result(result, temporary_reason, prefix, combined)

    counts, failure = _tests_counts(
        check, spec, start, prefix, combined, diagnostics, deadline,
    )
    if failure is not None:
        return _finish_test_result(failure, temporary_reason, prefix, combined)
    assert counts is not None
    ran, skipped, executed = counts
    if temporary_reason is not None:
        result = _tests_result(
            check,
            spec,
            start,
            prefix,
            "",
            outcome="pass",
            diagnostics=diagnostics,
            measurement={"tests": executed},
            tests_ran=ran,
            tests_skipped=skipped,
            report=False,
        )
        return _finish_test_result(
            result, temporary_reason, prefix, combined
        )
    return _tests_evidence(
        check,
        spec,
        start,
        prefix,
        evidence_dir,
        root,
        data_dir,
        ran,
        skipped,
        executed,
        diagnostics,
    )
