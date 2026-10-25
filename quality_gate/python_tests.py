"""Helpers for the python_tests adapter: the coverage prefix and test count."""
from __future__ import annotations

import sys
from pathlib import Path

from .coverage_tool import coverage_installation
from .policy import PythonTestsSpec


def coverage_prefix(root: Path, data_dir: Path) -> list[str]:
    """The in-place expansion of {python} and the value exported as QG_PYTHON."""
    installation = coverage_installation()
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


def parse_test_count(
    spec: PythonTestsSpec, output: str
) -> tuple[int | None, str | None]:
    match = spec.tests_pattern_re.search(output)
    if match is None:
        return (
            None,
            f"tests_pattern {spec.tests_pattern!r} did not match the "
            "command output",
        )
    text = match.group(1)
    try:
        return int(text), None
    except ValueError:
        return (
            None,
            f"tests_pattern {spec.tests_pattern!r} captured "
            f"{text!r}, which is not a test count",
        )
