"""Run selected pytest tests and report their collection, execution and origins.

This child runs as a script under isolated Python. It imports no gate package,
so measuring a project with the same package name leaves its imports clean.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def _module_files() -> set[Path]:
    files = set()
    for name, module in list(sys.modules.items()):
        if name == "__main__":
            continue
        if isinstance(module, ModuleType):
            filename = vars(module).get("__file__")
            if isinstance(filename, str):
                files.add(Path(filename).resolve())
    return files


def _canonical_selector_path(copy: Path, selector: str) -> Path:
    relative, delimiter, function = selector.partition("::")
    path = (copy / relative).resolve()
    if not path.is_relative_to(copy) or path == copy:
        raise ValueError(f"pytest selected path escapes its copy: {relative!r}")
    if delimiter:
        _validate_function_selector(path, copy, relative, function)
    return path


def _validate_function_selector(path: Path, copy: Path, relative: str, function: str) -> None:
    if path.relative_to(copy).as_posix() != relative or path.suffix != ".py":
        raise ValueError(f"invalid copied pytest function path: {relative!r}")
    if not function.startswith("test_") or not function.isidentifier():
        raise ValueError(f"invalid pytest function family: {function!r}")


def _selected_tests(copy: Path, tests: list[str]) -> tuple[set[Path], dict[str, Path]]:
    resolved = {test: _canonical_selector_path(copy, test) for test in tests}
    functions = {test: path for test, path in resolved.items() if "::" in test}
    if functions and len(functions) != len(tests):
        raise ValueError("expected unique pytest function selectors without file selections")
    return set(resolved.values()), functions


def _label_in_family(label: str, family: str) -> bool:
    return label == family or (label.startswith(f"{family}[") and label.endswith("]"))


def _function_family(item: pytest.Item, test_module: type, test_function: type) -> str | None:
    module = item.getparent(test_module)
    if module is None or not isinstance(item, test_function) or item.parent is not module:
        return None
    relative, _, label = item.nodeid.partition("::")
    if label != item.name or not _label_in_family(label, item.originalname):
        return None
    return f"{relative}::{item.originalname}"


def _matching_family(
    item: pytest.Item, expected: dict[str, Path], test_module: type, test_function: type,
) -> str | None:
    family = _function_family(item, test_module, test_function)
    return family if expected.get(family) == item.path.resolve() else None


def _collected_functions_match(evidence: Evidence, items: list[pytest.Item]) -> bool:
    if not evidence.expected_functions:
        return True
    found = {_matching_family(item, evidence.expected_functions, evidence.test_module, evidence.test_function)
             for item in items}
    return found == evidence.expected_functions.keys()


def _deselected_function(evidence: Evidence, items: list[pytest.Item]) -> bool:
    return any(
        _matching_family(
            item, evidence.expected_functions, evidence.test_module, evidence.test_function,
        ) is not None
        for item in items
    )


class Evidence:
    def __init__(
        self, expected_files: set[Path], test_module: type, failure_type: type,
        *, expected_functions: dict[str, Path] | None = None, test_function: type = object,
    ) -> None:
        self.expected_files = expected_files
        self.test_module = test_module
        self.failure_type = failure_type
        self.expected_functions = expected_functions or {}
        self.test_function = test_function
        self.collected: list[str] = []
        self.executed: list[str] = []
        self.assertions: list[str] = []
        self.errors: set[str] = set()

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        files = {item.path.resolve() for item in session.items}
        if not files:
            self.errors.add("pytest collected zero selected tests")
        elif files != self.expected_files:
            self.errors.add("pytest did not collect tests from exactly the selected copied files")
        for item in session.items:
            self._record_item(item)
        if not _collected_functions_match(self, session.items):
            self.errors.add("pytest did not collect exactly the selected copied function families")

    def _record_item(self, item: pytest.Item) -> None:
        self.collected.append(item.nodeid)
        module = item.getparent(self.test_module)
        if module is not None and Path(module.obj.__file__).resolve() != item.path.resolve():
            self.errors.add(f"pytest loaded a test module outside its copied file: {item.nodeid}")

    def pytest_deselected(self, items: list[pytest.Item]) -> None:
        if self.expected_functions and _deselected_function(self, items):
            self.errors.add("pytest deselected an instance of a selected copied function family")

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if report.failed:
            self.errors.add(f"pytest collection error in {report.nodeid}")

    def pytest_runtest_makereport(self, item: pytest.Item, call: pytest.CallInfo):
        result = yield
        report = result.get_result()
        if report.when == "call" and not report.skipped:
            self.executed.append(item.nodeid)
        if not report.failed:
            return
        if self._is_assertion(report, call):
            self.assertions.append(item.nodeid)
        else:
            self.errors.add(f"pytest {report.when} error in {item.nodeid}")

    def _is_assertion(self, report: pytest.TestReport, call: pytest.CallInfo) -> bool:
        return (
            report.when == "call" and call.excinfo is not None
            and isinstance(call.excinfo.value, (AssertionError, self.failure_type))
        )

    def write(self, path: Path, source: Path, target: Path) -> None:
        imported = _module_files()
        if target not in imported and not self.errors:
            self.errors.add(f"pytest did not import the measured module from the copy: {target.name}")
        leaked = sorted(filename for filename in imported if filename.is_relative_to(source))
        if leaked:
            self.errors.add(f"pytest imported from the source checkout: {leaked[0]}")
        path.write_text(json.dumps({
            "collected": self.collected,
            "executed": self.executed,
            "assertions": self.assertions,
            "errors": sorted(self.errors),
        }), encoding="utf-8")


def _import_path(copy: Path, original: Path, roots: list[str]) -> list[str]:
    local = []
    for relative in roots:
        path = (copy / relative).resolve()
        if not path.is_relative_to(copy):
            raise ValueError("pytest mutation import root escapes its copy")
        local.append(str(path))
    remaining = (entry for entry in sys.path if not Path(entry).resolve().is_relative_to(original))
    return list(dict.fromkeys([*local, str(copy), *remaining]))


def _main(argv: list[str]) -> int:
    import pytest

    source, report, relative_target, roots, *tests = argv
    original = Path(source).resolve()
    copy = Path.cwd().resolve()
    sys.path[:] = _import_path(copy, original, json.loads(roots))
    files, functions = _selected_tests(copy, tests)
    evidence = Evidence(
        files, pytest.Module, pytest.fail.Exception, expected_functions=functions,
        test_function=pytest.Function if functions else object,
    )
    pytest.hookimpl(hookwrapper=True, tryfirst=True)(Evidence.pytest_runtest_makereport)
    status = pytest.main(
        [f"--rootdir={copy}", "--", *(f"./{test}" for test in tests)], plugins=[evidence],
    )
    evidence.write(Path(report), original, (copy / relative_target).resolve())
    return status


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
