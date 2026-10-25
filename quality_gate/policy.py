"""Configuration loading and the policy data types."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MIN_TOKENS = 50


class GateError(Exception):
    """A check could not pass."""

    exit_code = 1


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


@dataclass(frozen=True)
class CloneConfig:
    classes: tuple[str, ...]
    min_tokens: int
    baseline: Path


@dataclass(frozen=True)
class Config:
    path: Path
    root: Path
    code_patterns: tuple[str, ...]
    code_shebangs: tuple[str, ...]
    classes: dict[str, ClassDef]
    rules: tuple[Rule, ...]
    max_bytes: int
    clones: CloneConfig | None


def _config_error(path: Path, key: str, expected: str, actual: str) -> ConfigError:
    return ConfigError(f"{path}: {key}: expected {expected}, got {actual}")


def _describe(value: object) -> str:
    if isinstance(value, (str, int, float, bool)):
        return f"{type(value).__name__} {value!r}"
    return type(value).__name__


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
    return value


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

    code = _required_table(data, "code", path, "code")
    patterns = _string_list(code, "patterns", path, "code.patterns")
    shebangs = _string_list(code, "shebangs", path, "code.shebangs")

    classes_raw = _required_table(data, "classes", path, "classes")
    classes: dict[str, ClassDef] = {}
    for name, raw in classes_raw.items():
        if not isinstance(raw, dict):
            raise _config_error(
                path, f"classes.{name}", "a table", _describe(raw)
            )
        classes[name] = ClassDef(
            name=name,
            code=_boolean(raw, "code", path, f"classes.{name}.code"),
            description=_string(
                raw, "description", path, f"classes.{name}.description"
            ),
        )

    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise _config_error(path, "rule", "an array of tables", _describe(raw_rules))
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        full_key = f"rule[{index}]"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
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

    hygiene = _optional_table(data, "hygiene", path, "hygiene")
    max_bytes = DEFAULT_MAX_BYTES
    if hygiene is not None:
        max_bytes = _integer(
            hygiene,
            "max_bytes",
            path,
            "hygiene.max_bytes",
            default=DEFAULT_MAX_BYTES,
            minimum=0,
        )

    clones_raw = _optional_table(data, "clones", path, "clones")
    clones: CloneConfig | None = None
    if clones_raw is not None:
        class_names = _string_list(clones_raw, "classes", path, "clones.classes")
        for class_name in class_names:
            if class_name not in classes:
                known = ", ".join(sorted(classes)) or "none"
                raise _config_error(
                    path,
                    "clones.classes",
                    f"a list of configured classes ({known})",
                    f"unknown class {class_name!r}",
                )
        min_tokens = _integer(
            clones_raw,
            "min_tokens",
            path,
            "clones.min_tokens",
            default=DEFAULT_MIN_TOKENS,
            minimum=1,
        )
        baseline_name = _string(clones_raw, "baseline", path, "clones.baseline")
        baseline = Path(baseline_name)
        if not baseline.is_absolute():
            baseline = root / baseline
        clones = CloneConfig(tuple(class_names), min_tokens, baseline)

    return Config(
        path=path,
        root=root,
        code_patterns=patterns,
        code_shebangs=shebangs,
        classes=classes,
        rules=tuple(rules),
        max_bytes=max_bytes,
        clones=clones,
    )
