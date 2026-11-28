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
FAILED_OUTCOMES = ("unexpected success", "failure", "error")
EVENT_OUTCOMES = ("passed", "skipped", "expected failure", *FAILED_OUTCOMES)
FIXTURE_OUTCOMES = {"fixture skipped": "skipped", "blocked": "error"}
RUNTIME_SUITE_REASON = "full run: suite runtime inputs are undeclared"


class ShardError(Exception):
    pass


def _journal_event(journal, event, value):
    print(json.dumps([event, value]), file=journal, flush=True)


def _decode_journal_frame(line, decode):
    if not line.endswith("\n"):
        raise ValueError("incomplete journal frame")
    frame = decode(line)
    if not isinstance(frame, list) or len(frame) != 2 or not isinstance(frame[0], str):
        raise ValueError(f"invalid journal frame: {frame!r}")
    return frame


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
        self.started = []
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
        self.passed_tests = []
        self.started.append(self.position)
        self.emit("started", self.position)
        super().startTest(test)
        self.started_at = time.monotonic()

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed_tests.append(test)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is None:
            self.passed_tests.append(subtest)

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
        stopped_at = time.monotonic()
        if test is not self.active_test:
            raise ShardError(f"unittest occurrence {_test_ids([test])[0]!r} stopped without starting")
        self.active_test = None
        if sys.exception() is None:
            events = list(self.events(test))
            outcome = _case_outcome(events)
            if outcome is None:
                name = self.ids[self.position]
                raise ShardError(f"unittest occurrence {name!r} stopped without an outcome")
            self.record(outcome, events, stopped_at - self.started_at)
        super().stopTest(test)

    def record(self, outcome, events, duration, fixture=None):
        record = [self.position, self.ids[self.position], outcome, events, duration, fixture]
        self.records.append(record)
        self.emit("terminal", record)

    def emit(self, event, value):
        if self.observe is not None:
            self.observe(event, value)

    def events(self, current):
        for test in self.passed_tests:
            yield self.event_id(test, current), "passed", ""
        yield from self.result_events(current)

    def result_events(self, current):
        for outcome, field in self.event_fields:
            entries = getattr(self, field)
            for entry in entries[self.offsets[field]:]:
                test, detail = entry if isinstance(entry, tuple) else (entry, "")
                if not isinstance(test, unittest.suite._ErrorHolder):
                    yield self.event_id(test, current), outcome, detail
            self.offsets[field] = len(entries)

    def event_id(self, test, current):
        return self.ids[self.position] if test is current else _test_ids([test])[0]


def _case_outcome(events):
    outcomes = {outcome for _, outcome, _ in events}
    if "passed" in outcomes:
        outcomes.discard("skipped")
    return max(outcomes, key=EVENT_OUTCOMES.index, default=None)


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
            result.record("fixture skipped" if outcome == "skipped" else "blocked", [], None, fixture)


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
    failed = []
    for position, test in enumerate(tests):
        if isinstance(test, unittest.loader._FailedTest):
            failed.append(position)
        else:
            cases.add(id(test))
    full = _suite_reason(full, loader, cases)
    header = {
        "ids": ids,
        "discovery_failed": failed,
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
    _validate_records(ids, positions, report["records"], report["fixtures"], started=report["started"])
    _journal_event(journal, "finished", None)
    return int(bool(failed_subjects(report["records"], report["fixtures"])))


def _run_affected(path):
    with path.with_suffix(".result.jsonl").open("w", encoding="utf-8") as journal:
        try:
            tests, ids, positions = _affected_discovery(path, journal)
            return _affected_execution(tests, ids, positions, journal)
        except ShardError as error:
            return _affected_error(journal, error)


def _affected_error(journal, error):
    if journal.tell() == 0:
        header = {"ids": [], "discovery_failed": [], "full": None, "discovery_errors": []}
        print(json.dumps(header), file=journal, flush=True)
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
    return {"ids": ids, "records": result.records, "fixtures": result.fixtures, "started": result.started}


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


def _valid_ids(ids):
    return isinstance(ids, list) and all(isinstance(name, str) for name in ids)


def _valid_event(event, outcomes):
    return (
        isinstance(event, (list, tuple)) and len(event) == 3
        and all(isinstance(item, str) for item in event) and event[1] in outcomes
    )


def _duration(value):
    return type(value) in (int, float) and 0 <= value <= sys.float_info.max


def _valid_events(events, outcomes):
    return isinstance(events, list) and all(map(functools.partial(_valid_event, outcomes=outcomes), events))


def _validate_fixture_record(label, record, fixture_events):
    _, _, outcome, events, duration, fixture = record
    if duration is not None or events != []:
        raise ShardError(f"{label}: invalid timing or case events for {outcome!r}")
    if (fixture, FIXTURE_OUTCOMES[outcome]) not in fixture_events:
        raise ShardError(f"{label}: missing setup fixture evidence for {outcome!r}: {fixture!r}")


def _validate_case_record(label, record):
    _, _, outcome, events, duration, fixture = record
    if not _valid_events(events, EVENT_OUTCOMES):
        raise ShardError(f"{label}: invalid unittest outcome events")
    if outcome != _case_outcome(events) or fixture is not None or not _duration(duration):
        raise ShardError(f"{label}: invalid outcome or duration: {outcome!r}, {duration!r}")


def _validate_terminal(ids, record, fixture_events):
    position, name, outcome, _, _, fixture = record
    label = _position_label(ids, position)
    if name != ids[position]:
        raise ShardError(f"{label}: expected the discovery ID, got {name!r}")
    if not isinstance(outcome, str):
        raise ShardError(f"{label}: invalid outcome {outcome!r}")
    if outcome in FIXTURE_OUTCOMES:
        if not isinstance(fixture, str):
            raise ShardError(f"{label}: expected a setup fixture ID, got {fixture!r}")
        _validate_fixture_record(label, record, fixture_events)
    else:
        _validate_case_record(label, record)


def _valid_position(position):
    return type(position) is int


def _validate_starts(ids, expected, records, started):
    measured = [record[0] for record in records if record[4] is not None]
    if started[:len(measured)] != measured:
        detail = _position_labels(ids, sorted(set(started) | set(measured)))
        raise ShardError(f"started occurrences disagree with measured records: {detail}")
    outstanding = started[len(measured):]
    allowed = expected[len(records):len(records) + 1]
    if outstanding not in ([], allowed):
        raise ShardError(f"unexpected outstanding starts: {_position_labels(ids, outstanding)}")


def _record_position(record):
    if not isinstance(record, list) or not record or not _valid_position(record[0]):
        raise ShardError(f"invalid terminal record: {record!r}")
    return record[0]


def _record_problem_detail(ids, expected, records):
    return "; ".join(
        f"{name} {_position_labels(ids, positions)}"
        for name, positions in _record_problems(expected, records).items() if positions
    )


def _validate_schedule(ids, expected, records):
    details = _record_problem_detail(ids, expected, records)
    if details:
        raise ShardError(
            f"shard record validation failed: expected one record per discovery position, got {details}"
        )
    positions = list(map(_record_position, records))
    if positions != expected:
        raise ShardError(f"out-of-order terminal records: {_position_labels(ids, positions)}")


def _validate_record_shapes(ids, records):
    if not isinstance(records, list):
        raise ShardError("expected a list of terminal records")
    for record in records:
        position = _record_position(record)
        if len(record) != 6:
            raise ShardError(f"{_position_label(ids, position)}: invalid terminal record shape")


def _setup_fixtures(fixtures):
    if not _valid_events(fixtures, ("error", "skipped")):
        raise ShardError("invalid unittest fixture events")
    return {
        (name, outcome) for name, outcome, _ in fixtures
        if name.startswith(("setUpClass (", "setUpModule ("))
    }


def _validate_started(ids, expected, records, started):
    if started is None:
        return
    if not isinstance(started, list) or not all(map(_valid_position, started)):
        raise ShardError(f"invalid started occurrences: {started!r}")
    _validate_starts(ids, expected, records, started)


def _validate_records(ids, expected, records, fixtures, *, complete=True, started=None):
    if not _valid_ids(ids):
        raise ShardError("expected a discovery ID list of strings")
    _validate_record_shapes(ids, records)
    expected = list(expected)
    _validate_schedule(ids, expected if complete else expected[:len(records)], records)
    fixture_events = _setup_fixtures(fixtures)
    for record in records:
        _validate_terminal(ids, record, fixture_events)
    _validate_started(ids, expected, records, started)


def validate_reports(ids, reports):
    for worker, report in enumerate(reports, 1):
        difference = _discovery_difference(ids, report["ids"], worker)
        if difference:
            raise ShardError(difference)
    records = sorted(_records(reports), key=_record_position)
    fixtures = [event for report in reports for event in report.get("fixtures", [])]
    _validate_records(ids, range(len(ids)), records, fixtures, started=_report_starts(reports))


def _report_starts(reports):
    if any("started" not in report for report in reports):
        return None
    return sorted(position for report in reports for position in report["started"])


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
        _execute(tests, ids, selected, functools.partial(_journal_event, journal))
    path.write_text(json.dumps(ids), encoding="utf-8")


def _worker_journal(path, interrupted):
    events = {name: [] for name in ("started", "terminal", "fixture")}
    try:
        with path.open(encoding="utf-8") as journal:
            _read_worker_frames(journal, events, interrupted)
    except FileNotFoundError:
        pass
    return events


def _read_worker_frames(journal, events, interrupted):
    for line in journal:
        if interrupted and not line.endswith("\n"):
            break
        event, value = _decode_journal_frame(line, json.loads)
        _append_worker_frame(events, event, value)


def _append_worker_frame(events, event, value):
    if event not in events:
        raise ValueError(f"unexpected worker journal event {event!r}")
    if event == "terminal":
        _record_position(value)
    events[event].append(value)


def _worker_failure(path, ids, positions, records, reason):
    missing = _record_problems(positions, records)["missing"]
    outstanding = _position_labels(ids, missing) or "none"
    with path.with_suffix(".log").open(encoding="utf-8", errors="replace") as stream:
        tail = "".join(deque(stream, maxlen=50))
    return ShardError(f"shard worker {path.name}: {reason}\nUnrecorded tests: {outstanding}\n{tail}")


def _load_worker_report(path):
    try:
        ids = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise ShardError(f"expected a readable JSON report at {path}, got {error}") from error
    if not _valid_ids(ids):
        raise ShardError(f"{path}: expected a discovery ID list of strings")
    return ids


def _worker_records(path, ids, positions, status):
    try:
        return _worker_journal(path.with_suffix(".jsonl"), interrupted=bool(status))
    except (OSError, ShardError, ValueError, RecursionError) as error:
        reason = f"invalid worker journal: {error}"
        if status:
            reason = f"expected exit status 0, got {status}; {reason}"
        raise _worker_failure(path, ids, positions, [], reason) from error


def _read_worker(process, path, ids, positions):
    status = process.wait()
    events = _worker_records(path, ids, positions, status)
    records, fixtures, started = events["terminal"], events["fixture"], events["started"]
    try:
        if status:
            raise ShardError(f"expected exit status 0, got {status}")
        discovered = _load_worker_report(path)
        if ids == discovered:
            _validate_records(ids, positions, records, fixtures, started=started)
        return {"ids": discovered, "records": records, "fixtures": fixtures, "started": started}
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


def failed_subjects(records, fixtures, labels=None):
    labels = {} if labels is None else labels
    tests = {labels.get(position, name) for position, name in _failed_occurrences(records)}
    fixtures = {name for name, outcome, _ in fixtures if outcome in FAILED_OUTCOMES}
    return sorted(tests | fixtures)


def _failed_occurrences(records):
    return [(record[0], record[1]) for record in records if record[2] in FAILED_OUTCOMES]


def _write_result_report(path, ids, reports, status):
    if path is None:
        return status
    document = {
        "ids": ids,
        "records": sorted(_records(reports), key=_record_position),
        "fixtures": [event for report in reports for event in report["fixtures"]],
    }
    try:
        path.write_text(json.dumps(document, allow_nan=False), encoding="utf-8")
    except OSError as error:
        print(f"unittest shards: cannot write test result report {path}: {error}", file=sys.stderr)
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
    parser.add_argument("--result-report", type=Path, metavar="PATH")
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
        if options is not None and options.result_report is not None:
            print(f"unittest shards: no test result report written to {options.result_report}",
                  file=sys.stderr)
        return 1
    status = _summary(reports, time.monotonic() - start)
    return _write_result_report(options.result_report, ids, reports, status)


def _entry(argv):
    if len(argv) == 2 and argv[0] == "--affected":
        return _run_affected(Path(argv[1]))
    return main(argv)


if __name__ == "__main__":
    with os.fdopen(os.dup(2), "w", encoding="utf-8") as diagnostics:
        faulthandler.enable(file=diagnostics)
        sys.exit(_entry(sys.argv[1:]))
