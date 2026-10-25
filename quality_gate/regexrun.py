#!/usr/bin/env python3
"""Evaluate the gate's configured regular expressions in a child process.

Invoked by a check as:

    python -I regexrun.py JOB

JOB is a JSON file {"text": ..., "patterns": {NAME: REGEX}}; the result is one
JSON object mapping each name to every match's captured groups.  A pattern
that backtracks catastrophically is therefore interruptible at the check's
remaining budget instead of stalling the gate.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def evaluate(
    job: dict[str, object],
) -> dict[str, list[list[str | None]]]:
    text = str(job["text"])
    patterns = job["patterns"]
    assert isinstance(patterns, dict)
    return {
        name: [
            list(match.groups())
            for match in re.finditer(pattern, text, re.MULTILINE)
        ]
        for name, pattern in patterns.items()
    }


def _run(argv: list[str]) -> int:
    job = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(evaluate(job), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_run(sys.argv))
