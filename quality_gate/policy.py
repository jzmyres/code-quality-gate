"""Configuration loading and the policy data types."""
from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from .elisp_lint import ElispLintSpec
    from .elisp_tests import ElispTestsSpec
    from .owners import OwnersSpec
    from .ratchet import BaselineEntry


DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MIN_TOKENS = 50
DEFAULT_BUDGET_SECONDS = 600
DEFAULT_TESTS_BUDGET_SECONDS = 900
DEFAULT_CRAP_THRESHOLD = 6.0
SUPPORTED_SCHEMA = 2
COMMON_CHECK_KEYS = ("adapter", "tier", "enforcement", "direction")
TOP_LEVEL_KEYS = (
    "schema",
    "code",
    "classes",
    "rule",
    "hygiene",
    "checks",
    "levels",
    "not_applicable",
    "protect",
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
    tests_pattern: str | None = None
    tests_pattern_re: re.Pattern[str] | None = None
    skipped_pattern: str | None = None
    skipped_pattern_re: re.Pattern[str] | None = None


@dataclass(frozen=True)
class CloneSpec:
    min_tokens: int


@dataclass(frozen=True)
class PythonTestsSpec:
    run: tuple[str, ...]
    tests_pattern: str
    tests_pattern_re: re.Pattern[str]
    skipped_pattern: str | None
    skipped_pattern_re: re.Pattern[str] | None
    budget_seconds: int


@dataclass(frozen=True)
class PythonCrapSpec:
    requires: str


@dataclass(frozen=True)
class ElispCrapSpec:
    requires: str


@dataclass(frozen=True)
class VerificationSpec:
    requires: str | None


AdapterSpec = Union[
    CommandSpec,
    CloneSpec,
    PythonTestsSpec,
    "ElispTestsSpec",
    "ElispLintSpec",
    PythonCrapSpec,
    ElispCrapSpec,
    VerificationSpec,
    "OwnersSpec",
]


@dataclass(frozen=True)
class CheckDef:
    id: str
    adapter: str
    tier: int
    enforcement: str
    metric_version: str
    evidence: tuple[str, ...]
    spec: AdapterSpec
    threshold: float | None
    baseline: Path | None
    direction: str = "max"
    effective_baseline: tuple[BaselineEntry, ...] | None = None


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
    protect_paths: tuple[str, ...] = ()
    prune_paths: dict[str, Path] = field(default_factory=dict)


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
            f"{path}: {where}: unknown key; expected an allowed key; allowed keys: {names}; got {key!r}"
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


def _number(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    default: float | None = None,
    minimum: float | None = None,
) -> float:
    if key not in parent:
        if default is None:
            raise _config_error(path, full_key, "a number", "missing")
        return default
    value = parent[key]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise _config_error(path, full_key, "a finite number", _describe(value))
    if minimum is not None and value < minimum:
        raise _config_error(
            path, full_key, f"a finite number >= {minimum}", str(value)
        )
    return float(value)


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


def _argv_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    values = _string_list(parent, key, path, full_key)
    for index, value in enumerate(values):
        if "\x00" in value:
            raise _config_error(
                path,
                f"{full_key}[{index}]",
                "an argument without NUL",
                "embedded NUL",
            )
    return values


def _one_group_pattern(
    raw: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str | None, re.Pattern[str] | None]:
    if key not in raw:
        return None, None
    text = _string(raw, key, path, full_key)
    try:
        pattern = re.compile(text, re.MULTILINE)
    except re.error as error:
        raise _config_error(
            path,
            full_key,
            "a valid regular expression",
            str(error),
        ) from error
    if pattern.groups != 1:
        raise _config_error(
            path,
            full_key,
            "a regular expression with one capture group",
            f"{pattern.groups} capture groups",
        )
    return text, pattern


def _test_patterns(
    raw: dict[str, Any], path: Path, full_key: str
) -> tuple[
    str | None,
    re.Pattern[str] | None,
    str | None,
    re.Pattern[str] | None,
]:
    if "skipped_pattern" in raw and "tests_pattern" not in raw:
        raise _config_error(
            path,
            f"{full_key}.skipped_pattern",
            "tests_pattern in the same check",
            "skipped_pattern without tests_pattern",
        )
    tests_text, tests_re = _one_group_pattern(
        raw, "tests_pattern", path, f"{full_key}.tests_pattern"
    )
    skipped_text, skipped_re = _one_group_pattern(
        raw, "skipped_pattern", path, f"{full_key}.skipped_pattern"
    )
    return tests_text, tests_re, skipped_text, skipped_re


def _parse_command(
    raw: dict[str, Any], path: Path, full_key: str
) -> CommandSpec:
    run = _argv_list(raw, "run", path, f"{full_key}.run")
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


def _parse_python_tests(
    raw: dict[str, Any], path: Path, full_key: str
) -> PythonTestsSpec:
    run = _argv_list(raw, "run", path, f"{full_key}.run")
    if not run:
        raise _config_error(
            path, f"{full_key}.run", "a non-empty argument list", "an empty list"
        )
    pattern_text, pattern, skipped_pattern_text, skipped_pattern = _test_patterns(
        raw, path, full_key
    )
    if pattern_text is None or pattern is None:
        raise _config_error(
            path,
            f"{full_key}.tests_pattern",
            "a regular expression with one capture group",
            "missing",
        )
    budget = _integer(
        raw,
        "budget_seconds",
        path,
        f"{full_key}.budget_seconds",
        default=DEFAULT_TESTS_BUDGET_SECONDS,
        minimum=1,
    )
    return PythonTestsSpec(
        tuple(run),
        pattern_text,
        pattern,
        skipped_pattern_text,
        skipped_pattern,
        budget,
    )


def _parse_direction(
    raw: dict[str, Any], path: Path, full_key: str
) -> str:
    if "direction" not in raw:
        return "max"
    direction = _string(raw, "direction", path, f"{full_key}.direction")
    if direction not in ("max", "min"):
        raise _config_error(
            path,
            f"{full_key}.direction",
            "one of max, min",
            _describe(direction),
        )
    return direction


def _requires_match(
    descriptor: Any, required: CheckDef | None
) -> bool:
    if required is None:
        return False
    if descriptor.requires_adapter is not None:
        return required.adapter == descriptor.requires_adapter
    if descriptor.requires_tests:
        return "tests" in required.evidence
    return True


def _test_producer_refusal(required: CheckDef | None) -> str:
    if required is None:
        return ""
    detail = " (no tests_pattern)" if required.adapter == "command" else ""
    return f" that produces no tests{detail}"


def _validate_requires(
    checks: dict[str, CheckDef],
    name: str,
    requires: str | None,
    path: Path,
    descriptor: Any,
) -> None:
    if requires is None:
        return
    required = checks.get(requires)
    if _requires_match(descriptor, required):
        return
    actual = (
        f"unknown check {requires!r}"
        if required is None
        else f"{requires!r} is a {required.adapter} check"
    )
    expected = f"the id of a {descriptor.requires_adapter} check declared earlier"
    if descriptor.requires_tests:
        expected = "the id of an earlier check that produces tests"
        actual += _test_producer_refusal(required)
    raise _config_error(
        path,
        f"checks.{name}.requires",
        expected,
        actual,
    )


def _check_header(
    raw: dict[str, Any], path: Path, full_key: str
) -> tuple[Any, int, str]:
    from .adapters import adapter_for, adapter_names

    adapter = _string(raw, "adapter", path, f"{full_key}.adapter")
    descriptor = adapter_for(adapter)
    if descriptor is None:
        names = ", ".join(adapter_names())
        raise _config_error(
            path,
            f"{full_key}.adapter",
            f"one of {names}",
            _describe(adapter),
        )
    _check_keys(raw, descriptor.allowed_keys(), path, full_key)
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
    return descriptor, tier, enforcement


def _validate_fixed_header(
    descriptor: Any, tier: int, enforcement: str, direction: str,
    path: Path, full_key: str,
) -> None:
    fixed = descriptor.fixed_header
    if fixed is None:
        return
    fixed_tier, fixed_enforcement, fixed_direction = fixed
    if tier != fixed_tier or enforcement != fixed_enforcement:
        raise _config_error(
            path, full_key,
            f"an {fixed_enforcement} tier {fixed_tier} {descriptor.name} check",
            f"tier {tier}, {enforcement}",
        )
    if direction != fixed_direction:
        raise _config_error(
            path, f"{full_key}.direction", fixed_direction, direction
        )


def _parse_check(
    name: str,
    raw: Any,
    root: Path,
    path: Path,
    checks: dict[str, CheckDef],
    candidate_root: Path,
) -> CheckDef:
    full_key = f"checks.{name}"
    if not name.strip():
        raise _config_error(path, full_key, "a non-empty check id", "an empty key")
    if not isinstance(raw, dict):
        raise _config_error(path, full_key, "a table", _describe(raw))
    descriptor, tier, enforcement = _check_header(raw, path, full_key)
    parse_root = candidate_root if descriptor.parse_candidate_inputs else root
    parts = descriptor.parse(raw, parse_root, path, full_key)
    direction = _parse_direction(raw, path, full_key)
    _validate_fixed_header(
        descriptor, tier, enforcement, direction, path, full_key
    )
    check = CheckDef(
        id=name,
        adapter=descriptor.name,
        tier=tier,
        enforcement=enforcement,
        metric_version=parts.metric_version,
        evidence=parts.evidence,
        spec=parts.spec,
        threshold=parts.threshold,
        baseline=parts.baseline,
        direction=direction,
    )
    _validate_requires(checks, name, parts.requires, path, descriptor)
    return check


def _parse_checks(
    data: dict[str, Any], root: Path, path: Path, *, validate_headers: bool = True,
    candidate_root: Path | None = None,
) -> dict[str, CheckDef]:
    raw_checks = _optional_table(data, "checks", path, "checks")
    if raw_checks is None:
        return {}
    checks: dict[str, CheckDef] = {}
    for name, raw in raw_checks.items():
        checks[name] = _parse_check(name, raw, root, path, checks, candidate_root or root)
    _validate_baselines(checks, path, validate_headers=validate_headers)
    return checks


def _header_string(
    data: dict[str, Any], key: str, path: Path, expected: str
) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _config_error(
            path,
            key,
            expected,
            "missing" if value is None else _describe(value),
        )
    return value


def _baseline_header(path: Path) -> tuple[str, str] | None:
    """Read a baseline's identity header, deferring malformed TOML to the check."""
    if not path.exists():
        return None
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None
    return (
        _header_string(
            data, "check", path, 'a baseline header check = "CHECK ID"'
        ),
        _header_string(
            data,
            "metric_version",
            path,
            'a baseline header metric_version = "VERSION"',
        ),
    )


def _baseline_key(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def _check_baseline_header(
    path: Path, name: str, check: CheckDef
) -> None:
    header = _baseline_header(path)
    if header is None:
        return
    expected = {
        "check": (check.id, f"(from checks.{name})"),
        "metric_version": (check.metric_version, f"(from checks.{name})"),
    }
    actual = {
        "check": header[0],
        "metric_version": header[1],
    }
    for key, value in actual.items():
        want, source = expected[key]
        if value != want:
            raise _config_error(
                path,
                key,
                f"{want!r} {source}",
                f"{value!r}",
            )


def _validate_baselines(
    checks: dict[str, CheckDef], path: Path, *, validate_headers: bool = True
) -> None:
    owners: dict[Path, str] = {}
    for name, check in checks.items():
        if check.baseline is None:
            continue
        key = _baseline_key(check.baseline)
        owner = owners.get(key)
        if owner is not None:
            raise _config_error(
                path,
                f"checks.{name}.baseline",
                "a baseline path used by exactly one check",
                f"{check.baseline} is also used by checks.{owner}",
            )
        owners[key] = name
        if validate_headers:
            _check_baseline_header(check.baseline, name, check)


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


def _declared_schema(data: dict[str, Any], path: Path) -> int:
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
    return SUPPORTED_SCHEMA


def _parse_hygiene(data: dict[str, Any], path: Path) -> int:
    hygiene = _optional_table(data, "hygiene", path, "hygiene")
    if hygiene is None:
        return DEFAULT_MAX_BYTES
    _check_keys(hygiene, ("max_bytes",), path, "hygiene")
    return _integer(
        hygiene,
        "max_bytes",
        path,
        "hygiene.max_bytes",
        default=DEFAULT_MAX_BYTES,
        minimum=0,
    )


def _parse_protect(data: dict[str, Any], path: Path) -> tuple[str, ...]:
    protect = _optional_table(data, "protect", path, "protect")
    if protect is None:
        return ()
    _check_keys(protect, ("paths",), path, "protect")
    return _optional_string_list(protect, "paths", path, "protect.paths")


def _config_from_data(
    root: Path, path: Path, data: dict[str, Any], *, validate_headers: bool = True,
    candidate_root: Path | None = None,
) -> Config:
    _check_keys(data, TOP_LEVEL_KEYS, path, "")
    schema = _declared_schema(data, path)

    code = _required_table(data, "code", path, "code")
    _check_keys(code, ("patterns", "shebangs"), path, "code")
    patterns = _string_list(code, "patterns", path, "code.patterns")
    shebangs = _string_list(code, "shebangs", path, "code.shebangs")

    classes = _parse_classes(data, path)
    rules = _parse_rules(data, path)
    max_bytes = _parse_hygiene(data, path)
    checks = _parse_checks(data, root, path, validate_headers=validate_headers, candidate_root=candidate_root)
    required_tiers = _parse_levels(data, path)
    not_applicable = _parse_not_applicable(data, classes, path)
    protect_paths = _parse_protect(data, path)

    return Config(
        path=path,
        root=root,
        schema=schema,
        code_patterns=patterns,
        code_shebangs=shebangs,
        classes=classes,
        rules=rules,
        max_bytes=max_bytes,
        checks=checks,
        required_tiers=required_tiers,
        not_applicable=not_applicable,
        protect_paths=protect_paths,
    )


def load_config(root: Path, *, validate_headers: bool = True, candidate_root: Path | None = None) -> Config:
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
    return _config_from_data(root, path, data, validate_headers=validate_headers,
                             candidate_root=candidate_root)
