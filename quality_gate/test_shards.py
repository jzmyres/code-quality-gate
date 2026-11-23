"""Discover and run a unittest suite across coverage-aware workers."""
from __future__ import annotations

import argparse
import contextlib
import itertools
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path


class ShardError(Exception):
    pass


class ShardResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.started = []

    def startTest(self, test):
        super().startTest(test)
        self.started.append(test)

    def events(self):
        for test, reason in self.skipped:
            yield test, "skipped", reason
        yield from self._tracebacks("expected failure", self.expectedFailures)
        for test in self.unexpectedSuccesses:
            yield test, "unexpected success", ""
        yield from self._tracebacks("failure", self.failures)
        yield from self._tracebacks("error", self.errors)

    @staticmethod
    def _tracebacks(outcome, entries):
        for test, traceback in entries:
            yield test, outcome, traceback


class ShardSuite(unittest.TestSuite):
    def __init__(self, tests):
        super().__init__(tests)
        self.blocked = []

    def _handleClassSetUp(self, test, result):
        super()._handleClassSetUp(test, result)
        if result._moduleSetUpFailed or getattr(type(test), "_classSetupFailed", False):
            self.blocked.append(test)


def _flatten(suite):
    for test in suite:
        if isinstance(test, unittest.suite.BaseTestSuite):
            yield from _flatten(test)
        else:
            yield test


def _discover(start, pattern):
    try:
        suite = unittest.TestLoader().discover(start, pattern)
    except ImportError as error:
        raise ShardError(
            f"discovery start {start!r}: expected an importable test directory, got {error}"
        ) from error
    return list(_flatten(suite))


def _module_blocks(modules):
    last = {module: index for index, module in enumerate(modules)}
    start = end = 0
    for index, module in enumerate(modules):
        end = max(end, last[module])
        if index == end:
            yield range(start, end + 1)
            start = end + 1


def assign_shares(tests, workers):
    modules = [type(test).__module__ for test in tests]
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


def _execute(tests, ids, positions=None):
    selected = range(len(tests)) if positions is None else positions
    cases = [tests[position] for position in selected]
    names = {id(tests[position]): ids[position] for position in selected}
    suite = ShardSuite(cases)
    result = ShardResult()
    suite.run(result)
    return _report(ids, result, suite.blocked, names)


def _report(ids, result, blocked, names):
    events = list(result.events())
    unnamed = [test for test, _, _ in events if id(test) not in names]
    names.update(zip(map(id, unnamed), _test_ids(unnamed), strict=True))
    return _format_report(ids, result.started, blocked, events, names)


def _format_report(ids, started, blocked, events, names):
    records = {id(test): [names[id(test)], "passed", []] for test in started}
    fixtures = _attach_events(events, records, names)
    omitted = [[names[id(test)], "blocked", []] for test in blocked]
    return {"ids": ids, "records": [*records.values(), *omitted], "fixtures": fixtures}


def _attach_events(events, records, names):
    fixtures = []
    for test, outcome, traceback in events:
        owner = test.test_case if isinstance(test, unittest.case._SubTest) else test
        record = records.get(id(owner))
        event = (names[id(test)], outcome, traceback)
        if record is None:
            fixtures.append(event)
        else:
            record[1] = outcome
            record[2].append(event)
    return fixtures


def _discovery_difference(expected, actual, worker):
    absent = "<end of discovery>"
    pairs = itertools.zip_longest(expected, actual, fillvalue=absent)
    for position, (want, got) in enumerate(pairs, 1):
        if want != got:
            return f"worker {worker} discovery differs at position {position}: expected {want!r}, got {got!r}"
    return None


def _record_problems(ids, reported):
    expected = set(ids)
    counts = Counter(reported)
    return {
        "missing": sorted(expected - counts.keys()),
        "unexpected": sorted(counts.keys() - expected),
        "duplicated": _duplicate_ids(counts),
        "duplicated in discovery": _duplicate_ids(Counter(ids)),
    }


def _duplicate_ids(counts):
    return sorted(test_id for test_id, count in counts.items() if count > 1)


def validate_reports(ids, reports):
    for worker, report in enumerate(reports, 1):
        difference = _discovery_difference(ids, report["ids"], worker)
        if difference:
            raise ShardError(difference)
    _validate_records(ids, _records(reports))


def _records(reports):
    return [record for report in reports for record in report["records"]]


def _validate_records(ids, records):
    problems = _record_problems(ids, (record[0] for record in records))
    details = ", ".join(f"{name} {values!r}" for name, values in problems.items() if values)
    if details:
        raise ShardError(
            f"shard record validation failed: expected one record per discovered id, got {details}"
        )


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


def _worker(options, tests, ids):
    plan_file, index = options.worker
    plan = json.loads(Path(plan_file).read_text(encoding="utf-8"))
    selected = plan["shares"][int(index)] if ids == plan["ids"] else []
    report = _execute(tests, ids, selected)
    _report_path(Path(plan_file), index).write_text(json.dumps(report), encoding="utf-8")


def _report_path(plan, index):
    return plan.with_name(f"worker-{index}.json")


def _read_worker(process, path, log):
    status = process.wait()
    if status:
        diagnostic = log.read_text(encoding="utf-8", errors="replace").strip()
        raise ShardError(f"shard worker {path.name}: expected exit status 0, got {status}\n{diagnostic}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ShardError(f"shard worker: expected a readable JSON report at {path}, got {error}") from error


def _stop_worker(process):
    if process.poll() is None:
        process.kill()
    process.wait()


def _spawn_worker(argv, output, log):
    try:
        with log.open("wb") as stderr:
            return subprocess.Popen(argv, stdout=output, stderr=stderr)
    except OSError as error:
        raise ShardError(f"shard worker {shlex.join(argv)}: expected to start, got {error}") from error


def _parallel(options, tests, ids, output):
    shares = assign_shares(tests, options.workers)
    prefix = _worker_prefix()
    command = [*prefix, str(Path(__file__).resolve()), "-s", options.start, "-p", options.pattern]
    with tempfile.TemporaryDirectory(prefix="qg-shards-") as directory, contextlib.ExitStack() as workers:
        plan = Path(directory) / "plan.json"
        plan.write_text(json.dumps({"ids": ids, "shares": shares}), encoding="utf-8")
        processes = []
        for index in range(len(shares)):
            argv = [*command, "--worker", str(plan), str(index)]
            path = _report_path(plan, index)
            log = path.with_suffix(".log")
            process = _spawn_worker(argv, output, log)
            workers.callback(_stop_worker, process)
            processes.append((process, path, log))
        return [_read_worker(*worker) for worker in processes]


def _print_details(events):
    labels = {"failure": "FAIL", "error": "ERROR", "unexpected success": "UNEXPECTED SUCCESS"}
    for test_id, outcome, traceback in events:
        if outcome in labels:
            print(f"{'=' * 70}\n{labels[outcome]}: {test_id}\n{'-' * 70}")
            print(traceback, end="")


def _events(ids, records, reports):
    for test_id in ids:
        yield from records[test_id][2]
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


def _summary(ids, reports, elapsed):
    records = {record[0]: record for record in _records(reports)}
    events = list(_events(ids, records, reports))
    _print_details(events)
    ran = sum(record[1] != "blocked" for record in records.values())
    failed, status = _summary_status(Counter(event[1] for event in events))
    noun = "test" if ran == 1 else "tests"
    print(f"{'-' * 70}\nRan {ran} {noun} in {elapsed:.3f}s\n")
    print(status)
    return int(failed)


def _options(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--start-directory", dest="start", required=True)
    parser.add_argument("-p", "--pattern", default="test*.py")
    parser.add_argument("-j", "--workers", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.workers < 1:
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


def main(argv=None):
    options = _options(argv)
    start = time.monotonic()
    try:
        with open(os.devnull, "w", encoding="utf-8") as output:
            with _quiet(output):
                tests = _discover(options.start, options.pattern)
                ids = _test_ids(tests)
                if options.worker:
                    _worker(options, tests, ids)
                    return 0
                if options.workers == 1:
                    reports = [_execute(tests, ids)]
                else:
                    reports = _parallel(options, tests, ids, output)
        validate_reports(ids, reports)
    except (ShardError, ImportError, OSError) as error:
        print(f"unittest shards: {error}", file=sys.stderr)
        return 1
    return _summary(ids, reports, time.monotonic() - start)


if __name__ == "__main__":
    sys.exit(main())
