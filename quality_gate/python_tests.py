"""Helpers for the python_tests adapter: the coverage prefix and test count."""
from __future__ import annotations

import sys
from pathlib import Path

from .coverage_tool import coverage_installation, write_coverage_config
from .policy import PythonTestsSpec


def coverage_prefix(root: Path, data_dir: Path) -> list[str]:
    """The in-place expansion of {python} and the value exported as QG_PYTHON."""
    installation = coverage_installation()
    write_coverage_config(data_dir, root)
    runner = Path(__file__).with_name("covrun.py")
    return [
        sys.executable,
        "-I",
        str(runner),
        str(data_dir),
        str(root),
        str(installation),
    ]


def expand_run(run: tuple[str, ...], prefix: list[str]) -> list[str]:
    expanded: list[str] = []
    for argument in run:
        if argument == "{python}":
            expanded.extend(prefix)
        else:
            expanded.append(argument)
    return expanded


def _capture_count(
    text: str, pattern: str, label: str
) -> tuple[int | None, str | None]:
    try:
        return int(text), None
    except ValueError:
        return (
            None,
            f"{label}_pattern {pattern!r} captured "
            f"{text!r}, which is not a test count",
        )


def _skipped_count(
    spec: PythonTestsSpec, output: str
) -> tuple[int | None, str | None]:
    if spec.skipped_pattern_re is None:
        return 0, None
    match = spec.skipped_pattern_re.search(output)
    if match is None:
        return 0, None
    assert spec.skipped_pattern is not None
    return _capture_count(
        match.group(1), spec.skipped_pattern, "skipped"
    )


def parse_test_summary(
    spec: PythonTestsSpec, output: str
) -> tuple[int | None, int | None, str | None]:
    matches = list(spec.tests_pattern_re.finditer(output))
    if not matches:
        return (
            None,
            None,
            f"tests_pattern {spec.tests_pattern!r} did not match the "
            "command output",
        )
    if len(matches) > 1:
        return (
            None,
            None,
            f"ambiguous test summary: tests_pattern {spec.tests_pattern!r} "
            f"matched {len(matches)} times",
        )
    ran, error = _capture_count(
        matches[0].group(1), spec.tests_pattern, "tests"
    )
    if error is not None:
        return None, None, error
    skipped, error = _skipped_count(spec, output)
    if error is not None:
        return None, None, error
    if skipped > ran:
        return (
            None,
            None,
            f"skipped {skipped} tests but only {ran} ran",
        )
    return ran, skipped, None


def parse_test_count(
    spec: PythonTestsSpec, output: str
) -> tuple[int | None, str | None]:
    ran, skipped, error = parse_test_summary(spec, output)
    if error is not None:
        return None, error
    assert ran is not None and skipped is not None
    return ran - skipped, None
