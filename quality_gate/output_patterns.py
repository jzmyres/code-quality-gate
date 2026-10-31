"""Shared output pattern validation, bounded matching and summary counts."""
from __future__ import annotations

import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .json_input import load_json
from .policy import _config_error, _string
from .runner import RunResult, analysis_step, mark_step, run


REGEX_RUNNER = Path(__file__).with_name("regexrun.py")


def _one_group_pattern(
    raw: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str | None, re.Pattern[str] | None]:
    if key not in raw:
        return None, None
    text = _string(raw, key, path, full_key)
    try:
        pattern = re.compile(text, re.MULTILINE)
    except re.error as error:
        raise _config_error(
            path,
            full_key,
            "a valid regular expression",
            str(error),
        ) from error
    if pattern.groups != 1:
        raise _config_error(
            path,
            full_key,
            "a regular expression with one capture group",
            f"{pattern.groups} capture groups",
        )
    return text, pattern


def _test_patterns(
    raw: dict[str, Any], path: Path, full_key: str
) -> tuple[
    str | None,
    re.Pattern[str] | None,
    str | None,
    re.Pattern[str] | None,
]:
    if "skipped_pattern" in raw and "tests_pattern" not in raw:
        raise _config_error(
            path,
            f"{full_key}.skipped_pattern",
            "tests_pattern in the same check",
            "skipped_pattern without tests_pattern",
        )
    tests_text, tests_re = _one_group_pattern(
        raw, "tests_pattern", path, f"{full_key}.tests_pattern"
    )
    skipped_text, skipped_re = _one_group_pattern(
        raw, "skipped_pattern", path, f"{full_key}.skipped_pattern"
    )
    return tests_text, tests_re, skipped_text, skipped_re


def _command_patterns(spec: Any) -> dict[str, str]:
    patterns: dict[str, str] = {}
    for name in ("tests", "skipped"):
        value = getattr(spec, f"{name}_pattern", None)
        if value is not None:
            patterns[name] = value
    must_match = getattr(spec, "must_match", None)
    if must_match is not None:
        patterns["must_match"] = must_match
    return patterns


def _pattern_matches(
    patterns: dict[str, str], text: str, budget_seconds: float
) -> tuple[dict[str, Any] | None, RunResult | None]:
    deadline = time.monotonic() + max(0.0, budget_seconds)
    with tempfile.TemporaryDirectory(prefix="qg-regex-") as temporary:
        job = Path(temporary) / "job.json"
        analysis_step("output matching preparation", _write_pattern_job, job, patterns, text)
        mark_step("output matching")
        result = run(
            [sys.executable, "-I", str(REGEX_RUNNER), str(job)],
            budget_seconds=max(0.0, deadline - time.monotonic()),
        )
    if result.execution != "completed" or result.returncode != 0:
        return None, result
    try:
        return analysis_step("output matching analysis", load_json, result.stdout_text), result
    except ValueError:
        return None, result


def _write_pattern_job(job: Path, patterns: dict[str, str], text: str) -> None:
    job.write_text(json.dumps({"text": text, "patterns": patterns}), encoding="utf-8")


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
    spec: Any, matches: list[list[str | None]]
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
    spec: Any,
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
