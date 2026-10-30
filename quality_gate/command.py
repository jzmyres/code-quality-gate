"""Configuration for the command adapter."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import policy
from .policy import DEFAULT_BUDGET_SECONDS, _config_error, _integer, _string, _test_patterns


@dataclass(frozen=True)
class CommandSpec:
    run: tuple[str, ...]
    budget_seconds: int
    must_match: str | None
    must_match_pattern: re.Pattern[str] | None
    tests_pattern: str | None = None
    tests_pattern_re: re.Pattern[str] | None = None
    skipped_pattern: str | None = None
    skipped_pattern_re: re.Pattern[str] | None = None


def _parse_command(
    raw: dict[str, Any], path: Path, full_key: str
) -> CommandSpec:
    run = policy._argv_list(raw, "run", path, f"{full_key}.run")
    if not run:
        raise _config_error(path, f"{full_key}.run", "a non-empty argument list", "an empty list")
    budget = _integer(
        raw,
        "budget_seconds",
        path,
        f"{full_key}.budget_seconds",
        default=DEFAULT_BUDGET_SECONDS,
        minimum=1,
    )
    must_match: str | None = None
    pattern: re.Pattern[str] | None = None
    if "must_match" in raw:
        must_match = _string(raw, "must_match", path, f"{full_key}.must_match")
        try:
            pattern = re.compile(must_match)
        except re.error as error:
            raise _config_error(
                path,
                f"{full_key}.must_match",
                "a valid regular expression",
                str(error),
            ) from error
    tests_text, tests_re, skipped_text, skipped_re = _test_patterns(
        raw, path, full_key
    )
    return CommandSpec(
        tuple(run),
        budget,
        must_match,
        pattern,
        tests_text,
        tests_re,
        skipped_text,
        skipped_re,
    )

