"""Read Bash syntax through the gate's pinned shfmt parser."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any


def _check_fields(node: dict[str, Any], fields: dict[str, type], filename: str) -> dict[str, Any]:
    for field, expected in fields.items():
        value: Any = node
        try:
            for key in field.split("."):
                value = value[key]
        except (KeyError, TypeError) as error:
            raise ValueError(f"{filename}: shfmt JSON missing field {field}") from error
        if type(value) is not expected:
            raise ValueError(f"{filename}: shfmt JSON field {field} must be {expected.__name__}")
    return node


def _decode_tree(
    output: bytes, filename: str, required_fields: Callable[[dict[str, Any]], dict[str, type]],
) -> dict[str, Any]:
    try:
        tree = json.loads(
            output, object_hook=lambda node: _check_fields(node, required_fields(node), filename),
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise ValueError(f"{filename}: invalid shfmt JSON: {error}") from error
    if not isinstance(tree, dict):
        raise ValueError(f"{filename}: shfmt JSON tree must be an object")
    return tree


def _require_time(filename: str, remaining: float) -> None:
    if remaining <= 0:
        raise ValueError(f"{filename}: shfmt deadline exceeded")


def _output(result: Any, filename: str, execution_outcome: Callable[[str], Any], failure: str) -> bytes:
    outcome = execution_outcome(result.execution)
    if outcome.budget:
        _require_time(filename, 0)
    if outcome.error:
        raise ValueError(f"{filename}: cannot run shfmt: {result.error}")
    if not outcome.completed or result.returncode != 0:
        detail = result.stderr_text.strip() or f"{result.execution}, exit {result.returncode}"
        raise ValueError(f"{filename}: {failure}: {detail}")
    return result.stdout


def parse(
    content: bytes, filename: str, required_fields: Callable[[dict[str, Any]], dict[str, type]],
    *, tool_binary: Callable[[str], Path], run: Callable[..., Any],
    execution_outcome: Callable[[str], Any], remaining_budget: Callable[[float], float],
    budget: int = 30, verify_reproduction: bool = False,
) -> dict[str, Any]:
    """Parse bytes and validate the caller's required dotted fields for each object."""

    def invoke(data: bytes, *flags: str, failure: str = "shfmt parse failed") -> bytes:
        _require_time(filename, remaining_budget(budget))
        result = run(
            [str(binary), *flags, "-ln=bash", "--filename", filename],
            stdin=data, budget_seconds=budget, capture_limit=None,
        )
        _require_time(filename, remaining_budget(budget))
        return _output(result, filename, execution_outcome, failure)

    _require_time(filename, remaining_budget(budget))
    binary = tool_binary("shfmt").absolute()
    encoded = invoke(content, "--to-json")
    tree = _decode_tree(encoded, filename, required_fields)
    if verify_reproduction:
        failure = "shfmt parser tree does not reproduce the file"
        reproduced = invoke(encoded, "--from-json", failure=failure)
        if reproduced != invoke(content):
            raise ValueError(f"{filename}: {failure}")
    _require_time(filename, remaining_budget(budget))
    return tree
