"""Discover and run a unittest suite across coverage-aware workers."""
from __future__ import annotations

import argparse
import contextlib
import faulthandler
import functools
import itertools
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter, deque
from pathlib import Path


CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP_MEMBERSHIP = Path("/proc/self/cgroup")
FAILED_OUTCOMES = ("failure", "error", "unexpected success")
RUNTIME_SUITE_REASON = "full run: suite runtime inputs are undeclared"


class ShardError(Exception):
    pass


def _journal_event(journal, event, value):
    print(json.dumps([event, value]), file=journal, flush=True)


class ShardResult(unittest.TextTestResult):
    event_fields = (
        ("skipped", "skipped"),
        ("expected failure", "expectedFailures"),
        ("unexpected success", "unexpectedSuccesses"),
        ("failure", "failures"),
        ("error", "errors"),
    )

    def __init__(self, stream, descriptions, verbosity, *, ids, observe):
        super().__init__(stream, descriptions, verbosity)
        self.ids = ids
        self.observe = observe
        self.records = []
        self.fixtures = []
        self.fixture_outcomes = {}
        self.offsets = dict.fromkeys((field for _, field in self.event_fields), 0)
        self.scheduled_test = self.active_test = None

    def startTest(self, test):
        if test is not self.scheduled_test:
            name = _test_ids([test])[0]
            raise ShardError(f"unexpected unittest occurrence {name!r}")
        if self.active_test is not None:
            raise ShardError(f"unittest occurrence {self.ids[self.position]!r} started again before stopping")
        self.active_test = test
        self.passed_subtest = False
        self.emit("started", self.position)
        super().startTest(test)

    def addSubTest(self, test, subtest, err):
        self.passed_subtest |= err is None
        super().addSubTest(test, subtest, err)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.fixture_event(test, "skipped", reason)

    def addError(self, test, err):
        super().addError(test, err)
        self.fixture_event(test, "error", self.errors[-1][1])

    def fixture_event(self, test, outcome, detail):
        if isinstance(test, unittest.suite._ErrorHolder):
            name = test.id()
            event = (name, outcome, detail)
            self.fixtures.append(event)
            self.fixture_outcomes[name] = outcome
            self.emit("fixture", event)

    def stopTest(self, test):
        if test is not self.active_test:
            raise ShardError(f"unittest occurrence {_test_ids([test])[0]!r} stopped without starting")
        self.active_test = None
        if sys.exception() is None:
            events = list(self.events(test))
            outcome = self.case_outcome(events)
            self.record(outcome, events)
        super().stopTest(test)

    def case_outcome(self, events):
        outcomes = [outcome for _, outcome, _ in events]
        if outcomes and (outcomes[-1] != "skipped" or not self.passed_subtest):
            return outcomes[-1]
        return "passed"

    def record(self, outcome, events):
        record = [self.position, self.ids[self.position], outcome, events]
        self.records.append(record)
        self.emit("terminal", record)

    def emit(self, event, value):
        if self.observe is not None:
            self.observe(event, value)

    def events(self, current):
        for outcome, field in self.event_fields:
            entries = getattr(self, field)
            for entry in entries[self.offsets[field]:]:
                test, detail = entry if isinstance(entry, tuple) else (entry, "")
                if not isinstance(test, unittest.suite._ErrorHolder):
                    name = self.ids[self.position] if test is current else _test_ids([test])[0]
                    yield name, outcome, detail
            self.offsets[field] = len(entries)


class ShardSuite(unittest.TestSuite):
    def __init__(self, tests, positions):
        super().__init__(tests)
        self.positions = iter(positions)

    def _handleClassSetUp(self, test, result):
        result.position = next(self.positions)
        result.active_test = result.scheduled_test = None
        super()._handleClassSetUp(test, result)
        fixture = _blocking_fixture(test, result)
        if fixture is None:
            result.scheduled_test = test
            return
        outcome = result.fixture_outcomes.get(fixture)
        if outcome is not None:
            result.record("fixture skipped" if outcome == "skipped" else "blocked", [])


def _blocking_fixture(test, result):
    cls = type(test)
    if result._moduleSetUpFailed:
        return f"setUpModule ({cls.__module__})"
    if getattr(cls, "_classSetupFailed", False):
        return f"setUpClass ({unittest.util.strclass(cls)})"
    return None


def _check_suite(suite):
    cls = type(suite)
    base = unittest.suite.BaseTestSuite
    if cls.run not in (base.run, unittest.TestSuite.run) or cls.__call__ is not base.__call__:
        raise ShardError(
            f"discovery suite {cls.__qualname__} in module {cls.__module__}: "
            "expected standard unittest suite execution, got a custom run or __call__"
        )


def _flatten(suite):
    _check_suite(suite)
    for test in suite:
        if isinstance(test, unittest.suite.BaseTestSuite):
            yield from _flatten(test)
        else:
            yield test


def _discover(start, pattern, loader=None):
    loader = unittest.TestLoader() if loader is None else loader
    try:
        suite = loader.discover(start, pattern)
    except ImportError as error:
        raise ShardError(
            f"discovery start {start!r}: expected an importable test directory, got {error}"
        ) from error
    return list(_flatten(suite))


class AffectedLoader(unittest.TestLoader):
    def __init__(self):
        super().__init__()
        self.used_hook = False
        self.sourced_cases = set()

    def loadTestsFromModule(self, module, *args, **kwargs):
        self.used_hook |= getattr(module, "load_tests", None) is not None
        suite = super().loadTestsFromModule(module, *args, **kwargs)
        if not self.used_hook and getattr(module, "__file__", None) is not None:
            self.sourced_cases.update(id(test) for test in _flatten(suite))
        return suite


def _suite_reason(full, loader, cases):
    if loader.used_hook:
        return "full run: unittest discovery used load_tests"
    if full not in (None, RUNTIME_SUITE_REASON):
        return full
    if not cases.issubset(loader.sourced_cases):
        return "full run: discovery returned a test without a source file"
    return full


def _affected_discovery(path, journal):
    plan = json.loads(path.read_text(encoding="utf-8"))
    options = _options(plan["argv"])
    loader = AffectedLoader()
    tests = _discover(options.start, options.pattern, loader)
    return _affected_schedule(tests, _test_ids(tests), loader, plan["full"], journal)


def _affected_schedule(tests, ids, loader, full, journal):
    cases = set()
    reported_ids = []
    failed = []
    for position, (test, name) in enumerate(zip(tests, ids, strict=True)):
        if isinstance(test, unittest.loader._FailedTest):
            reported_ids.append(None)
            failed.append(position)
        else:
            reported_ids.append(name)
            cases.add(id(test))
    full = _suite_reason(full, loader, cases)
    header = {
        "ids": reported_ids,
        "full": full,
        "discovery_errors": loader.errors,
    }
    print(json.dumps(header), file=journal, flush=True)
    positions = range(len(tests)) if full is not None else failed
    return tests, ids, positions


def _affected_event(journal, event, value):
    _journal_event(journal, event, value)
    if event == "started":
        return
    events = [value] if event == "fixture" else value[3]
    _print_details(events)
    for name, outcome, detail in events:
        if outcome == "skipped":
            print(f"skipped {name}: {detail}", flush=True)
    sys.stdout.flush()


def _affected_execution(tests, ids, positions, journal):
    report = _execute(tests, ids, positions, functools.partial(_affected_event, journal))
    _validate_records(ids, positions, report["records"])
    _journal_event(journal, "finished", None)
    return int(any(outcome in FAILED_OUTCOMES for _, outcome, _ in _events(report["records"], [report])))


def _run_affected(path):
    with path.with_suffix(".result.jsonl").open("w", encoding="utf-8") as journal:
        try:
            tests, ids, positions = _affected_discovery(path, journal)
            return _affected_execution(tests, ids, positions, journal)
        except ShardError as error:
            return _affected_error(journal, error)


def _affected_error(journal, error):
    if journal.tell() == 0:
        print(json.dumps({"ids": [], "full": None, "discovery_errors": []}), file=journal, flush=True)
    _journal_event(journal, "error", str(error))
    print(f"unittest shards: {error}", file=sys.stderr)
    return 1


def _module_blocks(modules):
    last = {module: index for index, module in enumerate(modules)}
    start = end = 0
    for index, module in enumerate(modules):
        end = max(end, last[module])
        if index == end:
            yield range(start, end + 1)
            start = end + 1


def _fixture_module(test, test_id):
    if isinstance(test, unittest.loader._FailedTest):
        return test_id.removeprefix("unittest.loader._FailedTest.")
    return type(test).__module__


def assign_shares(tests, ids, workers):
    modules = [_fixture_module(test, test_id) for test, test_id in zip(tests, ids, strict=True)]
    blocks = list(_module_blocks(modules))
    shares = [[] for _ in range(min(workers, len(blocks)))]
    for block in sorted(blocks, key=len, reverse=True):
        min(shares, key=len).extend(block)
    return [sorted(share) for share in shares]


@contextlib.contextmanager
def _without_coverage():
    module = sys.modules.get("coverage")
    active = module.Coverage.current() if module is not None else None
    with contextlib.ExitStack() as restore:
        if active is not None:
            active.stop()
            restore.callback(active.start)
        yield


def _test_ids(tests):
    with _without_coverage():
        return [test.id() for test in tests]


def _execute(tests, ids, positions=None, observe=None):
    selected = range(len(tests)) if positions is None else positions
    suite = ShardSuite([tests[position] for position in selected], selected)
    result_class = functools.partial(ShardResult, ids=ids, observe=observe)
    with open(os.devnull, "w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(
            stream=stream, resultclass=result_class, warnings=None if sys.warnoptions else "default",
        ).run(suite)
    return {"ids": ids, "records": result.records, "fixtures": result.fixtures}


def _discovery_difference(expected, actual, worker):
    absent = "<end of discovery>"
    pairs = itertools.zip_longest(expected, actual, fillvalue=absent)
    for position, (want, got) in enumerate(pairs, 1):
        if want != got:
            return f"worker {worker} discovery differs at position {position}: expected {want!r}, got {got!r}"
    return None


def _record_problems(expected, records):
    counts = Counter(record[0] for record in records)
    return {
        "missing": sorted(set(expected) - counts.keys()),
        "unexpected": sorted(counts.keys() - set(expected)),
        "duplicated": sorted(position for position, count in counts.items() if count > 1),
    }


def _position_label(ids, position):
    name = ids[position] if 0 <= position < len(ids) else "<outside discovery>"
    return f"position {position + 1} ({name!r})"


def _position_labels(ids, positions):
    return ", ".join(_position_label(ids, position) for position in positions)


def _validate_records(ids, expected, records):
    problems = _record_problems(expected, records)
    details = "; ".join(
        f"{name} {_position_labels(ids, positions)}" for name, positions in problems.items() if positions
    )
    if details:
        raise ShardError(
            f"shard record validation failed: expected one record per discovery position, got {details}"
        )


def validate_reports(ids, reports):
    for worker, report in enumerate(reports, 1):
        difference = _discovery_difference(ids, report["ids"], worker)
        if difference:
            raise ShardError(difference)
    _validate_records(ids, range(len(ids)), _records(reports))


def _records(reports):
    return [record for report in reports for record in report["records"]]


def _worker_prefix():
    if "QG_PYTHON" not in os.environ:
        return [sys.executable, "-I", "-B"]
    raw = os.environ["QG_PYTHON"]
    try:
        prefix = json.loads(raw)
    except ValueError as error:
        raise ShardError(f"QG_PYTHON: expected a JSON command prefix, got {raw!r}") from error
    if not _valid_prefix(prefix):
        raise ShardError(f"QG_PYTHON: expected a nonempty JSON list of command arguments, got {raw!r}")
    return prefix


def _valid_prefix(prefix):
    return isinstance(prefix, list) and bool(prefix) and all(isinstance(arg, str) and arg for arg in prefix)


def _worker(options):
    sys.stdout.reconfigure(line_buffering=True)
    plan_file, index = options.worker
    path = Path(plan_file).with_name(f"worker-{index}.json")
    plan = json.loads(Path(plan_file).read_text(encoding="utf-8"))
    tests = _discover(options.start, options.pattern)
    ids = _test_ids(tests)
    selected = plan["shares"][int(index)] if ids == plan["ids"] else []
    with path.with_suffix(".jsonl").open("w", encoding="utf-8") as journal:
        report = _execute(tests, ids, selected, functools.partial(_journal_event, journal))
    path.write_text(json.dumps({"ids": ids, "fixtures": report["fixtures"]}), encoding="utf-8")


def _completed_records(path):
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    events = (json.loads(line) for line in contents.split("\n")[:-1])
    return [record for event, record in events if event == "terminal"]


def _worker_failure(path, ids, positions, records, reason):
    missing = _record_problems(positions, records)["missing"]
    outstanding = _position_labels(ids, missing) or "none"
    with path.with_suffix(".log").open(encoding="utf-8", errors="replace") as stream:
        tail = "".join(deque(stream, maxlen=50))
    return ShardError(f"shard worker {path.name}: {reason}\nUnrecorded tests: {outstanding}\n{tail}")


def _load_worker_report(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ShardError(f"expected a readable JSON report at {path}, got {error}") from error


def _read_worker(process, path, ids, positions):
    status = process.wait()
    records = _completed_records(path.with_suffix(".jsonl"))
    try:
        if status:
            raise ShardError(f"expected exit status 0, got {status}")
        report = _load_worker_report(path)
        if ids == report["ids"]:
            _validate_records(ids, positions, records)
        return {**report, "records": records}
    except ShardError as error:
        raise _worker_failure(path, ids, positions, records, str(error)) from error


def _stop_worker(process):
    if process.poll() is None:
        process.kill()
    process.wait()


def _spawn_worker(argv, log):
    try:
        with log.open("wb") as output:
            return subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT)
    except OSError as error:
        raise ShardError(f"shard worker {shlex.join(argv)}: expected to start, got {error}") from error


def _parallel(options, tests, ids):
    shares = assign_shares(tests, ids, options.workers)
    prefix = _worker_prefix()
    command = [*prefix, str(Path(__file__).resolve()), "-s", options.start, "-p", options.pattern]
    with tempfile.TemporaryDirectory(prefix="qg-shards-") as directory, contextlib.ExitStack() as workers:
        plan = Path(directory) / "plan.json"
        plan.write_text(json.dumps({"ids": ids, "shares": shares}), encoding="utf-8")
        processes = []
        for index, positions in enumerate(shares):
            argv = [*command, "--worker", str(plan), str(index)]
            path = plan.with_name(f"worker-{index}.json")
            process = _spawn_worker(argv, path.with_suffix(".log"))
            workers.callback(_stop_worker, process)
            processes.append((process, path, ids, positions))
        return [_read_worker(*worker) for worker in processes]


def _print_details(events):
    labels = {"failure": "FAIL", "error": "ERROR", "unexpected success": "UNEXPECTED SUCCESS"}
    for test_id, outcome, traceback in events:
        if outcome in labels:
            print(f"{'=' * 70}\n{labels[outcome]}: {test_id}\n{'-' * 70}")
            print(traceback, end="")


def _events(records, reports):
    for record in records:
        yield from record[3]
    for report in reports:
        yield from report["fixtures"]


def _summary_status(counts):
    fields = {
        "failures": counts["failure"], "errors": counts["error"], "skipped": counts["skipped"],
        "expected failures": counts["expected failure"], "unexpected successes": counts["unexpected success"],
    }
    failed = any(counts[outcome] for outcome in ("failure", "error", "unexpected success"))
    status = "FAILED" if failed else "OK"
    suffix = ", ".join(f"{name}={count}" for name, count in fields.items() if count)
    return failed, f"{status} ({suffix})" if suffix else status


def _print_summary(ran, elapsed, status):
    noun = "test" if ran == 1 else "tests"
    print(f"{'-' * 70}\nRan {ran} {noun} in {elapsed:.3f}s\n")
    print(status)


def _summary(reports, elapsed):
    records = sorted(_records(reports))
    events = list(_events(records, reports))
    _print_details(events)
    outcomes = [record[2] for record in records]
    ran = len(records) - outcomes.count("blocked") - outcomes.count("fixture skipped")
    counts = Counter(event[1] for event in events)
    failed, status = _summary_status(counts)
    if ran == 0 and not counts["skipped"]:
        _print_summary(ran, elapsed, status if failed else "NO TESTS RAN")
        return 5
    _print_summary(ran, elapsed, status)
    return int(failed)


def _failed_ids(reports):
    tests = {name for _, name, outcome, _ in _records(reports) if outcome in FAILED_OUTCOMES}
    fixtures = {name for name, outcome, _ in _events((), reports) if outcome in FAILED_OUTCOMES}
    return sorted(tests | fixtures)


def _write_failed_report(path, reports, status):
    if path is None:
        return status
    try:
        path.write_text(json.dumps({"failed": _failed_ids(reports)}), encoding="utf-8")
    except OSError as error:
        print(f"unittest shards: cannot write failed test report {path}: {error}", file=sys.stderr)
        return 1
    return status


def _cpu_max_cores(content):
    quota, period = content.split()
    if not period.isdigit() or not (period_us := int(period)):
        raise ValueError
    if quota == b"max":
        return None
    if not quota.isdigit():
        raise ValueError
    return (int(quota) + period_us - 1) // period_us


def _cgroup_directory(root, membership):
    for line in membership.read_text(encoding="utf-8").splitlines():
        if not line.startswith("0::"):
            continue
        relative = Path(line[3:].lstrip("/"))
        directory = root / relative
        if ".." in relative.parts or not directory.is_dir():
            raise ShardError(f"{directory}: expected an existing cgroup directory under {root}")
        return directory
    return None


def _read_cpu_max(path):
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ShardError(f"{path}: expected readable CPU quota, content unavailable: {error}") from error
    try:
        return _cpu_max_cores(content)
    except ValueError as error:
        raise ShardError(f"{path}: expected a CPU quota and positive period, got {content!r}") from error


def _cgroup_cpu_quota(root, membership):
    directory = _cgroup_directory(root, membership)
    if directory is None:
        return None
    quotas = []
    for ancestor in (directory, *directory.parents):
        quota = _read_cpu_max(ancestor / "cpu.max")
        if quota is not None:
            quotas.append(quota)
        if ancestor == root:
            break
    return min(quotas, default=None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--start-directory", dest="start", required=True)
    parser.add_argument("-p", "--pattern", default="test*.py")
    parser.add_argument("-j", "--workers", type=int)
    parser.add_argument("--failed-report", type=Path, metavar="PATH")
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    return parser


def _options(argv):
    parser = build_parser()
    options = parser.parse_args(argv)
    if options.workers is None:
        if not options.worker:
            affinity = len(os.sched_getaffinity(0))
            quota = _cgroup_cpu_quota(CGROUP_ROOT, CGROUP_MEMBERSHIP)
            options.workers = max(1, min(affinity, quota if quota is not None else affinity))
    elif options.workers < 1:
        parser.error(f"--workers: expected an integer >= 1, got {options.workers}")
    return options


@contextlib.contextmanager
def _quiet(output):
    with contextlib.ExitStack() as restore:
        for descriptor in (1, 2):
            saved = os.dup(descriptor)
            restore.callback(os.close, saved)
            restore.callback(os.dup2, saved, descriptor)
            os.dup2(output.fileno(), descriptor)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            yield


def _run(options):
    with open(os.devnull, "w", encoding="utf-8") as output, _quiet(output):
        tests = _discover(options.start, options.pattern)
        ids = _test_ids(tests)
        if options.workers == 1:
            return ids, [_execute(tests, ids)]
    return ids, _parallel(options, tests, ids)


def main(argv=None):
    options = None
    try:
        options = _options(argv)
        start = time.monotonic()
        if options.worker:
            _worker(options)
            return 0
        ids, reports = _run(options)
        validate_reports(ids, reports)
    except (ShardError, ImportError, OSError) as error:
        print(f"unittest shards: {error}", file=sys.stderr)
        if options is not None and options.failed_report is not None:
            print(f"unittest shards: no failed test report written to {options.failed_report}",
                  file=sys.stderr)
        return 1
    status = _summary(reports, time.monotonic() - start)
    return _write_failed_report(options.failed_report, reports, status)


def _entry(argv):
    if len(argv) == 2 and argv[0] == "--affected":
        return _run_affected(Path(argv[1]))
    return main(argv)


if __name__ == "__main__":
    with os.fdopen(os.dup(2), "w", encoding="utf-8") as diagnostics:
        faulthandler.enable(file=diagnostics)
        sys.exit(_entry(sys.argv[1:]))
