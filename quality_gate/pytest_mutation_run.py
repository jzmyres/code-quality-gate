"""Run selected pytest files and report their collection, execution and origins.

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


class Evidence:
    def __init__(
        self, expected_files: set[Path], test_module: type, failure_type: type,
    ) -> None:
        self.expected_files = expected_files
        self.test_module = test_module
        self.failure_type = failure_type
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

    def _record_item(self, item: pytest.Item) -> None:
        self.collected.append(item.nodeid)
        module = item.getparent(self.test_module)
        if module is not None and Path(module.obj.__file__).resolve() != item.path.resolve():
            self.errors.add(f"pytest loaded a test module outside its copied file: {item.nodeid}")

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


def _main(argv: list[str]) -> int:
    import pytest

    source, report, relative_target, *tests = argv
    original = Path(source).resolve()
    copy = Path.cwd().resolve()
    sys.path[:] = [
        str(copy),
        *(entry for entry in sys.path if not Path(entry).resolve().is_relative_to(original)),
    ]
    evidence = Evidence({(copy / test).resolve() for test in tests}, pytest.Module, pytest.fail.Exception)
    pytest.hookimpl(hookwrapper=True, tryfirst=True)(Evidence.pytest_runtest_makereport)
    status = pytest.main(
        [f"--rootdir={copy}", "--", *(f"./{test}" for test in tests)], plugins=[evidence],
    )
    evidence.write(Path(report), original, (copy / relative_target).resolve())
    return status


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
