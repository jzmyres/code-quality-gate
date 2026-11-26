"""Configuration loading and the policy data types."""
from __future__ import annotations

import math
import operator
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, TypeVar

if TYPE_CHECKING:
    from .ratchet import BaselineEntry


DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BUDGET_SECONDS = 600
DEFAULT_TESTS_BUDGET_SECONDS = 900
DEFAULT_CRAP_THRESHOLD = 6.0
SUPPORTED_SCHEMA = 2
MODULE_CONTRACTS_ID = "module-contracts"
COMMON_CHECK_KEYS = ("adapter", "tier", "enforcement", "direction")
TOP_LEVEL_KEYS = (
    "schema",
    "code",
    "module_dirs",
    "classes",
    "rule",
    "hygiene",
    "checks",
    "levels",
    "not_applicable",
    "protect",
    "modules",
    "capabilities",
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
class CheckDef:
    id: str
    adapter: str
    tier: int
    enforcement: str
    metric_version: str
    evidence: tuple[str, ...]
    spec: object
    threshold: float | None
    baseline: Path | None
    direction: str = "max"
    effective_baseline: tuple[BaselineEntry, ...] | None = None
    required: tuple[str, ...] = ()


@dataclass(frozen=True)
class NotApplicable:
    class_name: str
    tier: int
    reason: str


@dataclass(frozen=True)
class ModuleDef:
    files: tuple[str, ...]
    entry_points: tuple[str, ...]
    allowed_dependencies: tuple[str, ...]
    protected_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityDef:
    owner: str
    entry_points: tuple[str, ...]


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
    modules: dict[str, ModuleDef]
    module_contracts: bool
    capabilities: dict[str, CapabilityDef]
    protect_paths: tuple[str, ...] = ()
    module_dirs: tuple[str, ...] | None = None
    shared_base: str | None = None


def _config_error(path: Path | str, key: str, expected: str, actual: str) -> ConfigError:
    return ConfigError(f"{path}: {key}: expected {expected}, got {actual}")


def _describe(value: object) -> str:
    if isinstance(value, (str, int, float, bool)):
        return f"{type(value).__name__} {value!r}"
    return type(value).__name__


_Location = TypeVar("_Location", Path, str)


def _unique(
    seen: set[Any],
    key: Any,
    path: _Location,
    where: str,
    expected: str,
    actual: str,
    error: Callable[[_Location, str, str, str], Exception],
) -> None:
    if key in seen:
        raise error(path, where, expected, actual)
    seen.add(key)


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


def _identity(value: Any) -> Any:
    return value


@dataclass(frozen=True)
class _ValueRule:
    expected: str
    checks: tuple[tuple[str, Any, str], ...]
    minimum: int | float | None = None
    maximum: int | float | None = None
    item: "_ValueRule | None" = None
    exclude: tuple[type, ...] = ()
    convert: Any = _identity


_STRING_ITEM = _ValueRule(
    "a string", (("type", (str,), "a string"),)
)
_STRING = _ValueRule(
    "a non-empty string",
    (
        ("type", (str,), "a string"),
        ("reject", operator.methodcaller("strip"), "a non-empty string"),
    ),
)
_STRING_ALLOW_EMPTY = _ValueRule(
    "a non-empty string", (("type", (str,), "a string"),)
)
_STRING_LIST = _ValueRule(
    "a list of strings",
    (("type", (list,), "a list of strings"),),
    item=_STRING_ITEM,
    convert=tuple,
)
_BOOLEAN = _ValueRule("a boolean", (("type", (bool,), "a boolean"),))
_TABLE = _ValueRule("a table", (("type", (dict,), "a table"),))
_INTEGER = _ValueRule(
    "an integer",
    (
        ("type", (int,), "an integer"),
        ("bound", ("minimum", operator.lt), "an integer >= {bound}"),
        ("bound", ("maximum", operator.gt), "an integer <= {bound}"),
    ),
    minimum=-math.inf,
    maximum=math.inf,
    exclude=(bool,),
)
_TIER = _ValueRule(
    "an integer",
    (
        ("type", (int,), "an integer"),
        ("bound", ("minimum", operator.lt), "an integer >= 1"),
        ("bound", ("maximum", operator.gt), "an integer <= 4"),
    ),
    minimum=1,
    maximum=4,
    exclude=(bool,),
)
_NUMBER = _ValueRule(
    "a number",
    (
        ("type", (int, float), "a finite number"),
        ("reject", math.isfinite, "a finite number"),
        ("bound", ("minimum", operator.lt), "a finite number >= {bound}"),
    ),
    minimum=-math.inf,
    maximum=math.inf,
    exclude=(bool,),
    convert=float,
)
_INTEGER_LIST = _ValueRule(
    "a list of integers",
    (("type", (list,), "a list of integers"),),
    item=_ValueRule(
        "an integer",
        (
            ("type", (int,), "an integer"),
            ("bound", ("minimum", operator.lt), "an integer from 1 to 4"),
            ("bound", ("maximum", operator.gt), "an integer from 1 to 4"),
        ),
        minimum=1,
        maximum=4,
        exclude=(bool,),
    ),
    convert=tuple,
)


def _read_scalar(
    path: Path | str,
    full_key: str,
    value: Any,
    rule: _ValueRule,
) -> Any:
    for kind, parameter, expected in rule.checks:
        match kind:
            case "type" if not all(
                (isinstance(value, parameter), not isinstance(value, rule.exclude))
            ):
                raise _config_error(path, full_key, expected, _describe(value))
            case "reject" if not parameter(value):
                raise _config_error(path, full_key, expected, _describe(value))
            case "bound" if parameter[1](value, getattr(rule, parameter[0])):
                bound = getattr(rule, parameter[0])
                raise _config_error(
                    path, full_key, expected.format(bound=bound), str(value)
                )
    return rule.convert(value)


def _read_value(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    rule: _ValueRule,
    *,
    default: Any = None,
) -> Any:
    if key not in parent:
        if default is not None:
            return default
        raise _config_error(path, full_key, rule.expected, "missing")
    value = parent[key]
    if rule.item is not None:
        if not isinstance(value, list):
            raise _config_error(path, full_key, rule.expected, _describe(value))
        return rule.convert(
            [
                _read_scalar(path, f"{full_key}[{index}]", item, rule.item)
                for index, item in enumerate(value)
            ]
        )
    return _read_scalar(path, full_key, value, rule)


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
    rule = _STRING_ALLOW_EMPTY if allow_empty else _STRING
    return _read_value(parent, key, path, full_key, rule)


def _string_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    return _read_value(parent, key, path, full_key, _STRING_LIST)


def _optional_string_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    if key not in parent:
        return ()
    return _string_list(parent, key, path, full_key)


def _validate_module_path(path: Path, item: str, value: str) -> None:
    if "\x00" in value or {"", ".", ".."}.intersection(value.split("/")):
        raise _config_error(path, item, "a canonical repository-relative path", repr(value))


def _validate_module_item(
    path: Path, item: str, field: str, value: str, modules: dict[str, Any],
) -> None:
    if field == "allowed_dependencies":
        if value not in modules:
            raise _config_error(path, item, "a declared module", f"unknown module {value!r}")
    else:
        _validate_module_path(path, item, value)


def _module_values(
    raw: dict[str, Any], name: str, field: str, path: Path, modules: dict[str, Any],
) -> tuple[str, ...]:
    key = f"modules.{name}.{field}"
    values = _string_list(raw, field, path, key)
    if field == "files" and not values:
        raise _config_error(path, key, "a non-empty list of file patterns", "an empty list")
    seen: set[str] = set()
    for index, value in enumerate(values):
        item = f"{key}[{index}]"
        _unique(seen, value, path, item, "a unique value", f"duplicate {value!r}", _config_error)
        _validate_module_item(path, item, field, value, modules)
    return values


def _validate_exact_path(path: Path, item: str, value: str) -> None:
    _validate_module_path(path, item, value)
    if set(value).intersection("*?[]"):
        raise _config_error(path, item, "an exact path without glob syntax", repr(value))


def _parse_modules(data: dict[str, Any], path: Path) -> dict[str, ModuleDef]:
    raw_modules = _read_value(data, "modules", path, "[modules]", _TABLE)
    fields = ("files", "entry_points", "allowed_dependencies")
    protected: set[str] = set()
    modules = {}
    for name in raw_modules:
        key = f"modules.{name}"
        raw = _read_value(raw_modules, name, path, key, _TABLE)
        _check_keys(raw, (*fields, "protected_paths"), path, key)
        protected_key = f"{key}.protected_paths"
        paths = _optional_string_list(raw, "protected_paths", path, protected_key)
        for index, value in enumerate(paths):
            item = f"{protected_key}[{index}]"
            _validate_exact_path(path, item, value)
            _unique(protected, value, path, item, "a unique protected path", f"duplicate {value!r}",
                    _config_error)
        modules[name] = ModuleDef(
            *(_module_values(raw, name, field, path, raw_modules) for field in fields), protected_paths=paths,
        )
    return modules


def _capability_entry_points(raw: dict[str, Any], path: Path, key: str) -> tuple[str, ...]:
    values = _string_list(raw, "entry_points", path, key)
    if not values:
        raise _config_error(path, key, "a non-empty list of exact paths", "an empty list")
    seen: set[str] = set()
    for index, value in enumerate(values):
        item = f"{key}[{index}]"
        _validate_exact_path(path, item, value)
        _unique(seen, value, path, item, "a unique value", f"duplicate {value!r}", _config_error)
    return values


def _parse_capabilities(
    data: dict[str, Any], path: Path, modules: dict[str, ModuleDef], module_contracts: bool,
) -> dict[str, CapabilityDef]:
    declarations = _read_value(data, "capabilities", path, "capabilities", _TABLE, default={})
    if declarations and not module_contracts:
        raise _config_error(path, "capabilities", "[checks.module-contracts]", "missing")
    capabilities = {}
    for name in declarations:
        key = f"capabilities.{name}"
        _read_scalar(path, key, name, _STRING)
        raw = _read_value(declarations, name, path, key, _TABLE)
        _check_keys(raw, ("owner", "entry_points"), path, key)
        owner_key = f"{key}.owner"
        owner = _string(raw, "owner", path, owner_key)
        if owner not in modules:
            raise _config_error(path, owner_key, "a declared module", f"unknown module {owner!r}")
        capabilities[name] = CapabilityDef(owner, _capability_entry_points(raw, path, f"{key}.entry_points"))
    return capabilities


def _scope(
    raw: dict[str, Any], path: Path, full_key: str, default: str
) -> str:
    if "scope" not in raw:
        return default
    scope = _string(raw, "scope", path, f"{full_key}.scope")
    if scope not in ("all", "changed"):
        raise ConfigError(
            f"{path}: {full_key}.scope: expected one of all, changed; "
            f"got {scope!r}"
        )
    return scope


def _names(
    raw: dict[str, Any],
    key: str,
    expected: tuple[str, ...],
    path: Path,
    full_key: str,
) -> None:
    if key not in raw:
        return
    values = _string_list(raw, key, path, f"{full_key}.{key}")
    if set(values) != set(expected) or len(values) != len(expected):
        raise ConfigError(
            f"{path}: {full_key}.{key}: expected exactly "
            f"{', '.join(expected)}; got {', '.join(values) or 'nothing'}"
        )


def _optional_string(
    parent: dict[str, Any], key: str, default: str, path: Path, full_key: str
) -> str:
    if key not in parent:
        return default
    return _string(parent, key, path, f"{full_key}.{key}")


def _optional_boolean(
    parent: dict[str, Any], key: str, default: bool, path: Path, full_key: str
) -> bool:
    if key not in parent:
        return default
    return _read_value(parent, key, path, f"{full_key}.{key}", _BOOLEAN)


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
    rule = replace(
        _INTEGER,
        minimum=minimum if minimum is not None else _INTEGER.minimum,
        maximum=maximum if maximum is not None else _INTEGER.maximum,
    )
    return _read_value(parent, key, path, full_key, rule, default=default)


def _number(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    default: float | None = None,
    minimum: float | None = None,
) -> float:
    rule = replace(
        _NUMBER, minimum=minimum if minimum is not None else _NUMBER.minimum
    )
    return _read_value(parent, key, path, full_key, rule, default=default)


def _integer_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[int, ...]:
    return _read_value(parent, key, path, full_key, _INTEGER_LIST)


def _parse_classes(
    data: dict[str, Any], path: Path
) -> dict[str, ClassDef]:
    classes_raw = _read_value(data, "classes", path, "classes", _TABLE)
    classes: dict[str, ClassDef] = {}
    for name, raw in classes_raw.items():
        full_key = f"classes.{name}"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        _check_keys(raw, ("code", "description", "checks"), path, full_key)
        checks = _optional_string_list(raw, "checks", path, f"{full_key}.checks")
        classes[name] = ClassDef(
            name=name,
            code=_read_value(raw, "code", path, f"{full_key}.code", _BOOLEAN),
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


def _validate_requires(
    checks: dict[str, CheckDef],
    name: str,
    requires: str | None,
    path: Path,
    descriptor: Any,
) -> None:
    from .adapters import adapter_for

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
        if required is not None:
            required_descriptor = adapter_for(required.adapter)
            actual += (
                " that produces no tests"
                f"{required_descriptor.no_tests_hint}"
            )
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


def _parse_check(
    name: str,
    raw: Any,
    root: Path,
    path: Path,
    checks: dict[str, CheckDef],
    candidate_root: Path,
    parse_candidate_inputs: bool = True,
) -> CheckDef:
    full_key = f"checks.{name}"
    if not name.strip():
        raise _config_error(path, full_key, "a non-empty check id", "an empty key")
    if not isinstance(raw, dict):
        raise _config_error(path, full_key, "a table", _describe(raw))
    descriptor, tier, enforcement = _check_header(raw, path, full_key)
    candidate = candidate_root if parse_candidate_inputs else None
    parse_root: Path | None = candidate if descriptor.parse_candidate_inputs else root
    parts = descriptor.parse(raw, parse_root, path, full_key)
    direction = _parse_direction(raw, path, full_key)
    required = descriptor.required_checks(parts.requires, list(checks.values()))
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
        required=required,
    )
    _validate_requires(checks, name, parts.requires, path, descriptor)
    return check


def _validate_crap_before_verification(
    checks: dict[str, CheckDef], path: Path
) -> None:
    verifications: list[str] = []
    for check in checks.values():
        if check.adapter == "verification":
            verifications.append(check.id)
        elif check.adapter == "python_crap" and verifications:
            raise _config_error(
                path,
                f"checks.{check.id}",
                "every python_crap check before every verification check, "
                "because verification counts the exclusions of every CRAP "
                "check, so it must come after them",
                f"python_crap check {check.id!r} declared after verification "
                f"check {verifications[-1]!r}",
            )


def _parse_checks(
    data: dict[str, Any], root: Path, path: Path, *, validate_headers: bool = True,
    candidate_root: Path | None = None, parse_candidate_inputs: bool = True,
) -> tuple[dict[str, CheckDef], str | None]:
    raw_checks = _optional_table(data, "checks", path, "checks")
    if raw_checks is None:
        return {}, None
    checks: dict[str, CheckDef] = {}
    shared_base = None
    for name, raw in raw_checks.items():
        if name == MODULE_CONTRACTS_ID:
            shared_base = _validate_module_contract_check(raw_checks, path)
            continue
        checks[name] = _parse_check(name, raw, root, path, checks,
                                    candidate_root or root, parse_candidate_inputs)
    _validate_crap_before_verification(checks, path)
    _validate_baselines(checks, path, validate_headers=validate_headers)
    return checks, shared_base


def _validate_module_contract_check(checks: dict[str, Any], path: Path) -> str | None:
    key = f"checks.{MODULE_CONTRACTS_ID}"
    raw = _read_value(checks, MODULE_CONTRACTS_ID, path, key, _TABLE)
    _check_keys(raw, ("adapter", "tier", "enforcement", "shared_base"), path, key)
    adapter = _string(raw, "adapter", path, f"{key}.adapter")
    if adapter != "module_contracts":
        raise _config_error(
            path, f"{key}.adapter", "module_contracts for this reserved check id", repr(adapter),
        )
    _integer(raw, "tier", path, f"{key}.tier", minimum=1, maximum=4)
    enforcement = _string(raw, "enforcement", path, f"{key}.enforcement")
    if enforcement != "enforced":
        raise _config_error(path, f"{key}.enforcement", "enforced", repr(enforcement))
    if "shared_base" not in raw:
        return None
    base_key = f"{key}.shared_base"
    shared_base = _string(raw, "shared_base", path, base_key)
    if "\x00" in shared_base:
        raise _config_error(path, base_key, "a revision without NUL characters", repr(shared_base))
    return shared_base


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
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError as error:
        raise ConfigError(
            f"{path}: expected an existing baseline file, got missing"
        ) from error
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
        if not check.baseline.is_file():
            raise _config_error(
                path,
                f"checks.{name}.baseline",
                "an existing baseline file or no baseline key",
                f"{check.baseline} does not exist",
            )
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


@dataclass(frozen=True)
class _FieldRule:
    key: str
    rule: _ValueRule
    known_class: bool = False


_NOT_APPLICABLE_FIELDS = (
    _FieldRule("class", _STRING, True),
    _FieldRule("tier", _TIER),
    _FieldRule("reason", _STRING),
)
_NOT_APPLICABLE_KEYS = tuple(field.key for field in _NOT_APPLICABLE_FIELDS)
_NOT_APPLICABLE_LIST = _ValueRule(
    "an array of tables",
    (("type", (list,), "an array of tables"),),
    convert=tuple,
)


def _parse_not_applicable(
    data: dict[str, Any], classes: dict[str, ClassDef], path: Path
) -> tuple[NotApplicable, ...]:
    raw_entries = _read_value(
        data,
        "not_applicable",
        path,
        "not_applicable",
        _NOT_APPLICABLE_LIST,
        default=[],
    )
    entries: list[NotApplicable] = []
    seen: set[tuple[str, int]] = set()
    for index, raw in enumerate(raw_entries):
        full_key = f"not_applicable[{index}]"
        _read_scalar(path, full_key, raw, _TABLE)
        _check_keys(raw, _NOT_APPLICABLE_KEYS, path, full_key)
        values: dict[str, Any] = {}
        for field in _NOT_APPLICABLE_FIELDS:
            value = _read_value(
                raw, field.key, path, f"{full_key}.{field.key}", field.rule
            )
            if field.known_class and value not in classes:
                known = ", ".join(sorted(classes)) or "none"
                raise _config_error(
                    path,
                    f"{full_key}.{field.key}",
                    f"a configured class ({known})",
                    f"unknown class {value!r}",
                )
            values[field.key] = value
        class_name = values["class"]
        tier = values["tier"]
        _unique(
            seen,
            (class_name, tier),
            path,
            full_key,
            "one entry per class and tier",
            f"duplicate {class_name!r} tier {tier}",
            _config_error,
        )
        entries.append(NotApplicable(class_name, tier, values["reason"]))
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


def _validate_module_directory(path: Path, key: str, directory: object) -> None:
    if not isinstance(directory, str):
        raise _config_error(path, key, "a string", repr(directory))
    if {"", ".", ".."}.intersection(directory.split("/")) or "\x00" in directory:
        raise _config_error(path, key, "a repository-relative directory path", repr(directory))


def _parse_module_dirs(data: dict[str, Any], path: Path) -> tuple[str, ...] | None:
    if "module_dirs" not in data:
        return None
    directories = data["module_dirs"]
    if not isinstance(directories, list):
        raise _config_error(path, "module_dirs", "a list of strings", repr(directories))
    seen: set[str] = set()
    for index, directory in enumerate(directories):
        key = f"module_dirs[{index}]"
        _validate_module_directory(path, key, directory)
        _unique(seen, directory, path, key, "a unique directory", f"duplicate {directory!r}", _config_error)
    return tuple(directories)


def _config_from_data(
    root: Path, path: Path, data: dict[str, Any], *, validate_headers: bool = True,
    candidate_root: Path | None = None, parse_candidate_inputs: bool = True,
) -> Config:
    _check_keys(data, TOP_LEVEL_KEYS, path, "")
    schema = _declared_schema(data, path)

    code = _read_value(data, "code", path, "code", _TABLE)
    _check_keys(code, ("patterns", "shebangs"), path, "code")
    patterns = _string_list(code, "patterns", path, "code.patterns")
    shebangs = _string_list(code, "shebangs", path, "code.shebangs")

    classes = _parse_classes(data, path)
    rules = _parse_rules(data, path)
    max_bytes = _parse_hygiene(data, path)
    checks, shared_base = _parse_checks(
        data, root, path, validate_headers=validate_headers, candidate_root=candidate_root,
        parse_candidate_inputs=parse_candidate_inputs,
    )
    required_tiers = _parse_levels(data, path)
    not_applicable = _parse_not_applicable(data, classes, path)
    protect_paths = _parse_protect(data, path)
    module_dirs = _parse_module_dirs(data, path)
    module_contracts = MODULE_CONTRACTS_ID in data.get("checks", {})
    modules = (
        _parse_modules(data, path) if module_contracts or "modules" in data else {}
    )

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
        module_dirs=module_dirs,
        modules=modules,
        module_contracts=module_contracts,
        capabilities=_parse_capabilities(data, path, modules, module_contracts),
        shared_base=shared_base,
    )


def load_config(root: Path, *, validate_headers: bool = True,
                candidate_root: Path | None = None,
                parse_candidate_inputs: bool = True) -> Config:
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
                             candidate_root=candidate_root,
                             parse_candidate_inputs=parse_candidate_inputs)
