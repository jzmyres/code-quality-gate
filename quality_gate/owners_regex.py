#!/usr/bin/env python3
"""Run last-resort owner regexes in a subprocess with the gate's budget."""

from __future__ import annotations

import bisect
import json
import re
import sys
from pathlib import Path


def _matches(source: str, patterns: list[str]) -> list[list[object]]:
    lines = [-1] + [index for index, char in enumerate(source) if char == "\n"]
    result = []
    for pattern in patterns:
        result.extend(_pattern_matches(source, pattern, lines))
    return result


def _pattern_matches(source: str, pattern: str, lines: list[int]) -> list[list[object]]:
    return [
        [pattern, bisect.bisect_left(lines, match.start()), match.start(), match.end()]
        for match in re.finditer(pattern, source, re.MULTILINE)
        if match.start() != match.end()
    ]


def _run(path: str) -> None:
    jobs = json.loads(Path(path).read_text(encoding="utf-8"))
    print(json.dumps({job["path"]: _matches(job["source"], job["patterns"]) for job in jobs}))


if __name__ == "__main__":
    _run(sys.argv[1])
