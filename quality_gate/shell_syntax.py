"""Read Bash syntax through the gate's pinned shfmt parser."""
from __future__ import annotations

import json
from collections.abc import Callable
from tempfile import TemporaryFile
from typing import Any

from .policy import GateError
from .runner import RunResult, execution_outcome, mark_step, remaining_budget, run
from .tools import tool_binary


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


def _run_shfmt(content: bytes, filename: str, budget: int) -> RunResult:
    mark_step(f"shfmt parsing {filename}")
    if remaining_budget(budget) <= 0:
        raise ValueError(f"{filename}: shfmt deadline exceeded")
    try:
        binary = tool_binary("shfmt").absolute()
        with TemporaryFile() as stdin:
            stdin.write(content)
            stdin.seek(0)
            return run(
                [str(binary), "--to-json", "-ln=bash", "--filename", filename],
                stdin=stdin.fileno(), budget_seconds=budget, capture_limit=None,
            )
    except (GateError, OSError) as error:
        raise ValueError(f"{filename}: cannot run shfmt: {error}") from error


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


def parse(
    content: bytes, filename: str, required_fields: Callable[[dict[str, Any]], dict[str, type]],
    *, budget: int = 30,
) -> dict[str, Any]:
    """Parse bytes and validate the caller's required dotted fields for each object."""
    result = _run_shfmt(content, filename, budget)
    outcome = execution_outcome(result.execution)
    if outcome.budget:
        raise ValueError(f"{filename}: shfmt deadline exceeded")
    if outcome.error:
        raise ValueError(f"{filename}: cannot run shfmt: {result.error}")
    if result.returncode != 0:
        detail = result.stderr_text.strip() or f"exit {result.returncode}"
        raise ValueError(f"{filename}: shfmt parse failed: {detail}")
    return _decode_tree(result.stdout, filename, required_fields)
