"""The Emacs Lisp default decision rules and repository overrides."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .policy import _check_keys, _config_error, _optional_table, _string_list


DEFAULT_RULES = {
    "branch": ("if", "when", "unless", "while", "dolist", "dotimes", "cl-dolist", "cl-dotimes",
               "cl-do", "cl-do*", "dolist-with-progress-reporter", "ignore-errors", "bound-and-true-p"),
    "operands": ("and", "or"),
    "cond": ("cond",),
    "bindings": ("if-let", "if-let*", "when-let", "when-let*", "and-let*"),
    "handlers": ("condition-case", "condition-case-unless-debug"),
    "case": ("pcase", "pcase-exhaustive", "cl-case", "cl-ecase", "cl-typecase"),
    "loop": ("cl-loop",),
    "loop_clauses": ("when", "if", "unless", "while", "until", "always", "never", "thereis"),
    "catch_all": ("t", "_", "otherwise"),
}


def _valid_symbol(value: str) -> bool:
    return bool(value) and value.isprintable() and not any(char.isspace() for char in value)


def _symbols(raw: dict[str, Any], family: str, path: Path, key: str) -> tuple[str, ...]:
    values = _string_list(raw, family, path, key)
    seen: set[str] = set()
    for index, value in enumerate(values):
        if not _valid_symbol(value):
            raise _config_error(
                path, f"{key}[{index}]", "a non-empty symbol name without whitespace or controls", repr(value)
            )
        if value in seen:
            raise _config_error(path, f"{key}[{index}]", "a unique symbol name", repr(value))
        seen.add(value)
    return values


def _validate_families(rules: dict[str, tuple[str, ...]], path: Path, key: str) -> None:
    seen: dict[str, str] = {}
    for family, values in rules.items():
        if family in ("loop_clauses", "catch_all"):
            continue
        for index, value in enumerate(values):
            if value in seen:
                raise _config_error(path, f"{key}.{family}[{index}]", "a form in only one decision family",
                                    f"{value!r} also in {key}.{seen[value]}")
            seen[value] = family


def parse_rules(raw: dict[str, Any], path: Path, key: str) -> dict[str, tuple[str, ...]]:
    """Replace supplied families, preserving the Emacs Lisp default for omitted ones."""
    overrides = _optional_table(raw, "decision_rules", path, key)
    rules = DEFAULT_RULES.copy()
    if overrides is not None:
        _check_keys(overrides, tuple(rules), path, key)
        for family in overrides:
            rules[family] = _symbols(overrides, family, path, f"{key}.{family}")
    _validate_families(rules, path, key)
    return rules
