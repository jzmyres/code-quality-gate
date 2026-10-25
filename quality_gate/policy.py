"""Configuration loading and the policy data types."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MIN_TOKENS = 50
DEFAULT_BUDGET_SECONDS = 600
SUPPORTED_SCHEMA = 1
SUPPORTED_ADAPTERS = ("command", "clones")
COMMON_CHECK_KEYS = ("adapter", "tier", "enforcement")
TOP_LEVEL_KEYS = (
    "schema",
    "code",
    "classes",
    "rule",
    "hygiene",
    "checks",
    "levels",
    "not_applicable",
)


class GateError(Exception):
    """A check could not pass."""

    exit_code = 1


class UnsupportedError(GateError):
    """The evidence a check needs is missing, so the check cannot pass."""


class UsageError(GateError):
    """The command or its configuration is malformed."""

    exit_code = 2


class ConfigError(UsageError):
    """quality-gate.toml is missing or invalid."""


@dataclass(frozen=True)
class Rule:
    index: int
    pattern: str
    class_name: str
    reason: str


@dataclass(frozen=True)
class ClassDef:
    name: str
    code: bool
    description: str
    checks: tuple[str, ...]


@dataclass(frozen=True)
class CommandSpec:
    run: tuple[str, ...]
    budget_seconds: int
    must_match: str | None
    must_match_pattern: re.Pattern[str] | None


@dataclass(frozen=True)
class CloneSpec:
    min_tokens: int
    baseline: Path


@dataclass(frozen=True)
class CheckDef:
    id: str
    adapter: str
    tier: int
    enforcement: str
    metric_version: str
    command: CommandSpec | None
    clones: CloneSpec | None
    threshold: float | None
    baseline: Path | None


@dataclass(frozen=True)
class NotApplicable:
    class_name: str
    tier: int
    reason: str


@dataclass(frozen=True)
class Config:
    path: Path
    root: Path
    schema: int
    code_patterns: tuple[str, ...]
    code_shebangs: tuple[str, ...]
    classes: dict[str, ClassDef]
    rules: tuple[Rule, ...]
    max_bytes: int
    checks: dict[str, CheckDef]
    required_tiers: tuple[int, ...]
    not_applicable: tuple[NotApplicable, ...]


def _config_error(path: Path, key: str, expected: str, actual: str) -> ConfigError:
    return ConfigError(f"{path}: {key}: expected {expected}, got {actual}")


def _describe(value: object) -> str:
    if isinstance(value, (str, int, float, bool)):
        return f"{type(value).__name__} {value!r}"
    return type(value).__name__


def _check_keys(
    table: dict[str, Any], allowed: tuple[str, ...], path: Path, full_key: str
) -> None:
    for key in table:
        if key in allowed:
            continue
        where = f"{full_key}.{key}" if full_key else key
        names = ", ".join(sorted(allowed))
        raise ConfigError(
            f"{path}: {where}: unknown key; allowed keys: {names}"
        )


def _required_table(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> dict[str, Any]:
    if key not in parent:
        raise _config_error(path, full_key, "a table", "missing")
    value = parent[key]
    if not isinstance(value, dict):
        raise _config_error(path, full_key, "a table", _describe(value))
    return value


def _optional_table(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> dict[str, Any] | None:
    if key not in parent:
        return None
    value = parent[key]
    if not isinstance(value, dict):
        raise _config_error(path, full_key, "a table", _describe(value))
    return value


def _string(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    allow_empty: bool = False,
) -> str:
    if key not in parent:
        raise _config_error(path, full_key, "a non-empty string", "missing")
    value = parent[key]
    if not isinstance(value, str):
        raise _config_error(path, full_key, "a string", _describe(value))
    if not allow_empty and not value.strip():
        raise _config_error(path, full_key, "a non-empty string", _describe(value))
    return value


def _string_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    if key not in parent:
        raise _config_error(path, full_key, "a list of strings", "missing")
    value = parent[key]
    if not isinstance(value, list):
        raise _config_error(path, full_key, "a list of strings", _describe(value))
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise _config_error(
                path, f"{full_key}[{index}]", "a string", _describe(item)
            )
    return tuple(value)


def _optional_string_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    if key not in parent:
        return ()
    return _string_list(parent, key, path, full_key)


def _boolean(parent: dict[str, Any], key: str, path: Path, full_key: str) -> bool:
    if key not in parent:
        raise _config_error(path, full_key, "a boolean", "missing")
    value = parent[key]
    if not isinstance(value, bool):
        raise _config_error(path, full_key, "a boolean", _describe(value))
    return value


def _integer(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if key not in parent:
        if default is None:
            raise _config_error(path, full_key, "an integer", "missing")
        return default
    value = parent[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _config_error(path, full_key, "an integer", _describe(value))
    if minimum is not None and value < minimum:
        raise _config_error(path, full_key, f"an integer >= {minimum}", str(value))
    if maximum is not None and value > maximum:
        raise _config_error(path, full_key, f"an integer <= {maximum}", str(value))
    return value


def _integer_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[int, ...]:
    if key not in parent:
        raise _config_error(path, full_key, "a list of integers", "missing")
    value = parent[key]
    if not isinstance(value, list):
        raise _config_error(path, full_key, "a list of integers", _describe(value))
    result: list[int] = []
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, int):
            raise _config_error(
                path, f"{full_key}[{index}]", "an integer", _describe(item)
            )
        if item < 1 or item > 4:
            raise _config_error(
                path, f"{full_key}[{index}]", "an integer from 1 to 4", str(item)
            )
        result.append(item)
    return tuple(result)


def _parse_classes(
    data: dict[str, Any], path: Path
) -> dict[str, ClassDef]:
    classes_raw = _required_table(data, "classes", path, "classes")
    classes: dict[str, ClassDef] = {}
    for name, raw in classes_raw.items():
        full_key = f"classes.{name}"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        _check_keys(raw, ("code", "description", "checks"), path, full_key)
        checks = _optional_string_list(raw, "checks", path, f"{full_key}.checks")
        classes[name] = ClassDef(
            name=name,
            code=_boolean(raw, "code", path, f"{full_key}.code"),
            description=_string(raw, "description", path, f"{full_key}.description"),
            checks=checks,
        )
    return classes


def _parse_rules(data: dict[str, Any], path: Path) -> tuple[Rule, ...]:
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise _config_error(path, "rule", "an array of tables", _describe(raw_rules))
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        full_key = f"rule[{index}]"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        _check_keys(raw, ("pattern", "class", "reason"), path, full_key)
        rules.append(
            Rule(
                index=index,
                pattern=_string(
                    raw, "pattern", path, f"{full_key}.pattern", allow_empty=True
                ),
                class_name=_string(raw, "class", path, f"{full_key}.class"),
                reason=_string(
                    raw, "reason", path, f"{full_key}.reason", allow_empty=True
                ),
            )
        )
    return tuple(rules)


def _parse_command(
    raw: dict[str, Any], path: Path, full_key: str
) -> CommandSpec:
    run = _string_list(raw, "run", path, f"{full_key}.run")
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
    return CommandSpec(tuple(run), budget, must_match, pattern)


def _parse_clones(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> CloneSpec:
    min_tokens = _integer(
        raw,
        "min_tokens",
        path,
        f"{full_key}.min_tokens",
        default=DEFAULT_MIN_TOKENS,
        minimum=1,
    )
    baseline_name = _string(raw, "baseline", path, f"{full_key}.baseline")
    baseline = Path(baseline_name)
    if not baseline.is_absolute():
        baseline = root / baseline
    return CloneSpec(min_tokens, baseline)


def _parse_checks(
    data: dict[str, Any], root: Path, path: Path
) -> dict[str, CheckDef]:
    raw_checks = _optional_table(data, "checks", path, "checks")
    if raw_checks is None:
        return {}
    checks: dict[str, CheckDef] = {}
    for name, raw in raw_checks.items():
        full_key = f"checks.{name}"
        if not name.strip():
            raise _config_error(path, full_key, "a non-empty check id", "an empty key")
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        adapter = _string(raw, "adapter", path, f"{full_key}.adapter")
        if adapter not in SUPPORTED_ADAPTERS:
            names = ", ".join(SUPPORTED_ADAPTERS)
            raise _config_error(
                path,
                f"{full_key}.adapter",
                f"one of {names}",
                _describe(adapter),
            )
        if adapter == "command":
            allowed = (*COMMON_CHECK_KEYS, "run", "budget_seconds", "must_match")
        else:
            allowed = (*COMMON_CHECK_KEYS, "min_tokens", "baseline")
        _check_keys(raw, allowed, path, full_key)
        tier = _integer(
            raw, "tier", path, f"{full_key}.tier", minimum=1, maximum=4
        )
        enforcement = _string(raw, "enforcement", path, f"{full_key}.enforcement")
        if enforcement not in ("enforced", "advisory"):
            raise _config_error(
                path,
                f"{full_key}.enforcement",
                "one of enforced, advisory",
                _describe(enforcement),
            )
        command: CommandSpec | None = None
        clones: CloneSpec | None = None
        baseline: Path | None = None
        threshold: float | None = None
        if adapter == "command":
            command = _parse_command(raw, path, full_key)
            metric_version = "command-exit/1"
        else:
            clones = _parse_clones(raw, root, path, full_key)
            baseline = clones.baseline
            threshold = 0
            metric_version = "jscpd-clone-occurrences/1"
        checks[name] = CheckDef(
            id=name,
            adapter=adapter,
            tier=tier,
            enforcement=enforcement,
            metric_version=metric_version,
            command=command,
            clones=clones,
            threshold=threshold,
            baseline=baseline,
        )
    return checks


def _parse_levels(
    data: dict[str, Any], path: Path
) -> tuple[int, ...]:
    levels = _optional_table(data, "levels", path, "levels")
    if levels is None:
        return (1,)
    _check_keys(levels, ("required_tiers",), path, "levels")
    if "required_tiers" not in levels:
        return (1,)
    required = _integer_list(levels, "required_tiers", path, "levels.required_tiers")
    if 1 not in required:
        raise _config_error(
            path,
            "levels.required_tiers",
            "a list of tiers containing 1",
            repr(list(required)),
        )
    return required


def _parse_not_applicable(
    data: dict[str, Any], classes: dict[str, ClassDef], path: Path
) -> tuple[NotApplicable, ...]:
    raw_entries = data.get("not_applicable", [])
    if not isinstance(raw_entries, list):
        raise _config_error(
            path, "not_applicable", "an array of tables", _describe(raw_entries)
        )
    entries: list[NotApplicable] = []
    seen: set[tuple[str, int]] = set()
    for index, raw in enumerate(raw_entries):
        full_key = f"not_applicable[{index}]"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        _check_keys(raw, ("class", "tier", "reason"), path, full_key)
        class_name = _string(raw, "class", path, f"{full_key}.class")
        if class_name not in classes:
            known = ", ".join(sorted(classes)) or "none"
            raise _config_error(
                path,
                f"{full_key}.class",
                f"a configured class ({known})",
                f"unknown class {class_name!r}",
            )
        tier = _integer(
            raw, "tier", path, f"{full_key}.tier", minimum=1, maximum=4
        )
        reason = _string(raw, "reason", path, f"{full_key}.reason")
        key = (class_name, tier)
        if key in seen:
            raise _config_error(
                path,
                full_key,
                "one entry per class and tier",
                f"duplicate {class_name!r} tier {tier}",
            )
        seen.add(key)
        entries.append(NotApplicable(class_name, tier, reason))
    return tuple(entries)


def load_config(root: Path) -> Config:
    path = root / "quality-gate.toml"
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError:
        raise ConfigError(
            f"{path}: expected a configuration file, got missing"
        ) from None
    except OSError as error:
        raise ConfigError(
            f"{path}: expected a readable configuration file, got {error}"
        ) from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ConfigError(f"{path}: expected valid TOML, got {error}") from error

    _check_keys(data, TOP_LEVEL_KEYS, path, "")
    if "schema" not in data:
        raise _config_error(path, "schema", str(SUPPORTED_SCHEMA), "missing")
    declared_schema = data["schema"]
    if (
        isinstance(declared_schema, bool)
        or not isinstance(declared_schema, int)
        or declared_schema != SUPPORTED_SCHEMA
    ):
        raise _config_error(
            path, "schema", str(SUPPORTED_SCHEMA), _describe(declared_schema)
        )

    code = _required_table(data, "code", path, "code")
    _check_keys(code, ("patterns", "shebangs"), path, "code")
    patterns = _string_list(code, "patterns", path, "code.patterns")
    shebangs = _string_list(code, "shebangs", path, "code.shebangs")

    classes = _parse_classes(data, path)
    rules = _parse_rules(data, path)

    hygiene = _optional_table(data, "hygiene", path, "hygiene")
    max_bytes = DEFAULT_MAX_BYTES
    if hygiene is not None:
        _check_keys(hygiene, ("max_bytes",), path, "hygiene")
        max_bytes = _integer(
            hygiene,
            "max_bytes",
            path,
            "hygiene.max_bytes",
            default=DEFAULT_MAX_BYTES,
            minimum=0,
        )

    checks = _parse_checks(data, root, path)
    required_tiers = _parse_levels(data, path)
    not_applicable = _parse_not_applicable(data, classes, path)

    return Config(
        path=path,
        root=root,
        schema=SUPPORTED_SCHEMA,
        code_patterns=patterns,
        code_shebangs=shebangs,
        classes=classes,
        rules=rules,
        max_bytes=max_bytes,
        checks=checks,
        required_tiers=required_tiers,
        not_applicable=not_applicable,
    )
