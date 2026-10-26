"""Helpers for the python_tests adapter: the coverage prefix and test count."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from .coverage_tool import (
    registry_dir,
    write_coverage_config,
)
from .policy import PythonTestsSpec
from .tools import installed_tool


def coverage_prefix(root: Path, data_dir: Path) -> list[str]:
    """The in-place expansion of {python} and the value exported as QG_PYTHON."""
    tool, installation = installed_tool("coverage")
    config_file = write_coverage_config(data_dir, root)
    registry = registry_dir(data_dir)
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
        str(config_file),
        str(registry),
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
    text: str | None, pattern: str, label: str
) -> tuple[int | None, str | None]:
    if text is None:
        return 0, None
    if re.fullmatch(r"[0-9]+", text) is None:
        return (
            None,
            f"{label}_pattern {pattern!r} captured "
            f"{text!r}, which is not a test count "
            "(expected a non-negative integer)",
        )
    return int(text), None


def _skipped_from_matches(
    spec: PythonTestsSpec, matches: list[list[str | None]]
) -> tuple[int | None, str | None]:
    if spec.skipped_pattern_re is None or not matches:
        return 0, None
    if len(matches) > 1:
        return (
            None,
            f"ambiguous skipped summary: skipped_pattern "
            f"{spec.skipped_pattern!r} matched {len(matches)} times",
        )
    assert spec.skipped_pattern is not None
    return _capture_count(
        matches[0][0], spec.skipped_pattern, "skipped"
    )


def summarize_matches(
    spec: PythonTestsSpec,
    tests_matches: list[list[str | None]],
    skipped_matches: list[list[str | None]],
) -> tuple[int | None, int | None, str | None]:
    if not tests_matches:
        return (
            None,
            None,
            f"tests_pattern {spec.tests_pattern!r} did not match the "
            "command output",
        )
    if len(tests_matches) > 1:
        return (
            None,
            None,
            f"ambiguous test summary: tests_pattern {spec.tests_pattern!r} "
            f"matched {len(tests_matches)} times",
        )
    ran, error = _capture_count(
        tests_matches[0][0], spec.tests_pattern, "tests"
    )
    if error is not None:
        return None, None, error
    skipped, error = _skipped_from_matches(spec, skipped_matches)
    if error is not None:
        return None, None, error
    if skipped > ran:
        return (
            None,
            None,
            f"skipped {skipped} tests but only {ran} ran",
        )
    return ran, skipped, None
