"""Read Bash syntax through the gate's pinned shfmt parser."""
from __future__ import annotations

import json
from collections.abc import Callable
from subprocess import SubprocessError, run
from typing import Any

from .policy import GateError
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


def parse(
    content: bytes, filename: str, required_fields: Callable[[dict[str, Any]], dict[str, type]],
    *, budget: int = 30,
) -> dict[str, Any]:
    """Parse bytes and validate the caller's required dotted fields for each object."""
    try:
        binary = tool_binary("shfmt").absolute()
        result = run(
            [str(binary), "--to-json", "-ln=bash", "--filename", filename],
            input=content, capture_output=True, timeout=budget, check=False,
        )
    except (GateError, OSError, SubprocessError) as error:
        raise ValueError(f"{filename}: cannot run shfmt: {error}") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{filename}: shfmt parse failed: {detail or f'exit {result.returncode}'}")
    try:
        tree = json.loads(
            result.stdout, object_hook=lambda node: _check_fields(node, required_fields(node), filename),
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise ValueError(f"{filename}: invalid shfmt JSON: {error}") from error
    if not isinstance(tree, dict):
        raise ValueError(f"{filename}: shfmt JSON tree must be an object")
    return tree
