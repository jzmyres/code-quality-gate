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


class ShardError(Exception):
    pass


class ShardResult(unittest.TextTestResult):
    event_fields = (
        ("skipped", "skipped"),
        ("expected failure", "expectedFailures"),
        ("unexpected success", "unexpectedSuccesses"),
        ("failure", "failures"),
        ("error", "errors"),
    )

    def __init__(self, stream, descriptions, verbosity, *, ids, journal):
        super().__init__(stream, descriptions, verbosity)
        self.ids = ids
        self.journal = journal
        self.records = []
        self.fixtures = []
        self.offsets = dict.fromkeys((field for _, field in self.event_fields), 0)

    def startTest(self, test):
        self.fixtures.extend(self.events())
        super().startTest(test)

    def stopTest(self, test):
        events = list(self.events(test))
        outcome = events[-1][1] if events else "passed"
        self.record(outcome, events)
        super().stopTest(test)

    def record(self, outcome, events):
        record = [self.position, self.ids[self.position], outcome, events]
        if self.journal is None:
            self.records.append(record)
        else:
            print(json.dumps(record), file=self.journal, flush=True)

    def events(self, current=None):
        for outcome, field in self.event_fields:
            entries = getattr(self, field)
            for entry in entries[self.offsets[field]:]:
                test, detail = entry if isinstance(entry, tuple) else (entry, "")
                name = self.ids[self.position] if test is current else _test_ids([test])[0]
                yield name, outcome, detail
            self.offsets[field] = len(entries)


class ShardSuite(unittest.TestSuite):
    def __init__(self, tests, positions):
        super().__init__(tests)
        self.positions = iter(positions)

    def _handleClassSetUp(self, test, result):
        super()._handleClassSetUp(test, result)
        result.position = next(self.positions)
        if result._moduleSetUpFailed or getattr(type(test), "_classSetupFailed", False):
            result.record("blocked", [])


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


def _execute(tests, ids, positions=None, journal=None):
    selected = range(len(tests)) if positions is None else positions
    suite = ShardSuite([tests[position] for position in selected], selected)
    result_class = functools.partial(ShardResult, ids=ids, journal=journal)
    with open(os.devnull, "w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(
            stream=stream, resultclass=result_class, warnings=None if sys.warnoptions else "default",
        ).run(suite)
    result.fixtures.extend(result.events())
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
        report = _execute(tests, ids, selected, journal)
    path.write_text(json.dumps({"ids": ids, "fixtures": report["fixtures"]}), encoding="utf-8")


def _completed_records(path):
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in contents.split("\n")[:-1]]


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
    ran = len(records) - outcomes.count("blocked")
    counts = Counter(event[1] for event in events)
    failed, status = _summary_status(counts)
    if ran == 0 and not counts["skipped"]:
        _print_summary(ran, elapsed, status if failed else "NO TESTS RAN")
        return 5
    _print_summary(ran, elapsed, status)
    return int(failed)


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


def _options(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--start-directory", dest="start", required=True)
    parser.add_argument("-p", "--pattern", default="test*.py")
    parser.add_argument("-j", "--workers", type=int)
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
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
        return 1
    return _summary(reports, time.monotonic() - start)


if __name__ == "__main__":
    with os.fdopen(os.dup(2), "w", encoding="utf-8") as diagnostics:
        faulthandler.enable(file=diagnostics)
        sys.exit(main())
