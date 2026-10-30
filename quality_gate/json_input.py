"""Decode JSON evidence without ambiguous object names or non-JSON constants."""
from __future__ import annotations

import json
from typing import Any


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"expected unique JSON object names, got duplicate name {name[:128]!r}")
        result[name] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError(f"expected a JSON value, got non-JSON constant {value[:128]!r}")


def load_json(text: str) -> Any:
    """Decode text, raising ValueError for invalid JSON, duplicate names or constants."""
    return json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
