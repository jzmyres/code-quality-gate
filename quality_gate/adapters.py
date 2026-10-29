"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, its location coverage, number display, metric
direction per subject kind, whether it produces normalized test results, the
baseline extras it trusts, and its baseline and budget handling.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from . import ratchet
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    DEFAULT_MIN_TOKENS,
    CloneSpec,
    ElispCrapSpec,
    PythonCrapSpec,
    VerificationSpec,
    _integer,
    _number,
    _parse_command,
    _parse_python_tests,
    _string,
)


def _default_budget(_spec: Any) -> int:
    from .checks import CLONE_BUDGET_SECONDS

    return CLONE_BUDGET_SECONDS


@dataclass(frozen=True)
class AdapterContext:
    """One check's inputs, passed unchanged to its descriptor's runner."""

    root: Path
    config: Any
    check: Any
    files: list[str]
    classes: dict[str, str]
    prefix: str
    prior: dict[str, Any]


@dataclass(frozen=True)
class ParsedSpec:
    """One check's parsed adapter specification and its shared properties."""

    spec: Any
    metric_version: str
    evidence: tuple[str, ...]
    threshold: float | None = None
    baseline: Path | None = None
    requires: str | None = None


@dataclass(frozen=True)
class AdapterDescriptor:
    """Everything the core needs to know about one adapter."""

    name: str
    keys: tuple[str, ...]
    parse: Callable[[dict[str, Any], Path, Path, str], ParsedSpec]
    run: Callable[..., Any]
    location_coverage: str = "none"
    display: Callable[[float], str] = ratchet._number
    directions: Mapping[str, str] = field(default_factory=dict)
    default_direction: str | None = None
    produces_tests: bool = False
    extras: tuple[str, ...] = ()
    requires_adapter: str | None = None
    requires_tests: bool = False
    fixed_header: tuple[int, str, str] | None = None
    budget: Callable[[Any], int] = _default_budget
    entry_direction: Callable[[str, str], str] | None = None
    parse_candidate_inputs: bool = False

    def allowed_keys(self) -> tuple[str, ...]:
        return (*COMMON_CHECK_KEYS, *self.keys)

    def direction(self, kind: str, configured: str) -> str:
        if kind in self.directions:
            return self.directions[kind]
        return self.default_direction or configured

    def direction_for_subject(self, subject: str, configured: str) -> str:
        if self.entry_direction is not None:
            return self.entry_direction(subject, configured)
        return configured


def _baseline(raw: dict[str, Any], root: Path, path: Path, full_key: str) -> Path:
    name = _string(raw, "baseline", path, f"{full_key}.baseline")
    baseline = Path(name)
    if not baseline.is_absolute():
        baseline = root / baseline
    return baseline


def _command_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    spec = _parse_command(raw, path, full_key)
    evidence = ("tests",) if spec.tests_pattern is not None else ("static",)
    return ParsedSpec(spec, "command-exit/1", evidence)


def _clones_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    min_tokens = _integer(
        raw,
        "min_tokens",
        path,
        f"{full_key}.min_tokens",
        default=DEFAULT_MIN_TOKENS,
        minimum=1,
    )
    baseline = _baseline(raw, root, path, full_key)
    return ParsedSpec(
        CloneSpec(min_tokens),
        "jscpd-clone-occurrences/1",
        ("duplication",),
        threshold=0,
        baseline=baseline,
    )


def _python_tests_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    spec = _parse_python_tests(raw, path, full_key)
    return ParsedSpec(spec, "test-count/1", ("tests",))


def _elisp_tests_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .elisp_tests import parse_spec

    return ParsedSpec(parse_spec(raw, root, path, full_key), "test-count/1", ("tests",))


def _elisp_lint_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .elisp_lint import parse_spec

    return ParsedSpec(parse_spec(raw, root, path, full_key), "elisp-lint/1", ("static",))


def _crap_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str,
    spec_type: Any, version: str,
) -> ParsedSpec:
    requires = _string(raw, "requires", path, f"{full_key}.requires")
    baseline = _baseline(raw, root, path, full_key)
    threshold = _number(
        raw,
        "threshold",
        path,
        f"{full_key}.threshold",
        default=DEFAULT_CRAP_THRESHOLD,
        minimum=0,
    )
    return ParsedSpec(
        spec_type(requires),
        version,
        ("crap",),
        threshold=threshold,
        baseline=baseline,
        requires=requires,
    )


def _python_crap_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    return _crap_spec(raw, root, path, full_key, PythonCrapSpec, "python-lines/1")


def _elisp_crap_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    return _crap_spec(raw, root, path, full_key, ElispCrapSpec, "elisp-edebug/1")


def _verification_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    requires: str | None = None
    if "requires" in raw:
        requires = _string(raw, "requires", path, f"{full_key}.requires")
    baseline = _baseline(raw, root, path, full_key)
    return ParsedSpec(
        VerificationSpec(requires),
        "verification/1",
        (),
        threshold=0,
        baseline=baseline,
        requires=requires,
    )


def _owners_spec(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> ParsedSpec:
    from .owners import parse_owners

    baseline = _baseline(raw, root, path, full_key)
    return ParsedSpec(
        parse_owners(raw, path, full_key),
        "owners/1",
        ("static",),
        threshold=0,
        baseline=baseline,
    )


def _verification_entry_direction(subject: str, configured: str) -> str:
    if subject.startswith("tests:") and subject.endswith(":executed"):
        return "min"
    return "max"


def _runner(attribute: str) -> Callable[..., Any]:
    def run(
        root: Path,
        config: Any,
        check: Any,
        files: list[str],
        classes: dict[str, str],
        *,
        prefix: str,
        prior: dict[str, Any],
    ) -> Any:
        from . import checks

        context = AdapterContext(
            root, config, check, files, classes, prefix, prior
        )
        return getattr(checks, attribute)(context)

    return run


def _spec_budget(spec: Any) -> int:
    return spec.budget_seconds


ADAPTERS: dict[str, AdapterDescriptor] = {}


def register_adapter(descriptor: AdapterDescriptor) -> AdapterDescriptor:
    default = descriptor.default_direction or "max"
    if descriptor.entry_direction is None and set(descriptor.directions.values()) - {default}:
        kinds = ", ".join(
            f"{kind}={direction}" for kind, direction in descriptor.directions.items()
        )
        raise ValueError(
            f"adapter {descriptor.name!r}: kinds ({kinds}) differ from default "
            f"{default!r}; expected entry_direction to decide each subject's direction"
        )
    ADAPTERS[descriptor.name] = descriptor
    return descriptor


def remove_adapter(name: str) -> None:
    ADAPTERS.pop(name, None)


def adapter_for(name: str | AdapterDescriptor) -> AdapterDescriptor | None:
    if isinstance(name, AdapterDescriptor):
        return name
    return ADAPTERS.get(name)


def adapter_names() -> tuple[str, ...]:
    return tuple(ADAPTERS)


register_adapter(AdapterDescriptor(
    "command",
    ("run", "budget_seconds", "must_match", "tests_pattern", "skipped_pattern"),
    _command_spec,
    _runner("_run_command"),
    budget=_spec_budget,
))
register_adapter(AdapterDescriptor(
    "clones",
    ("min_tokens", "baseline"),
    _clones_spec,
    _runner("_run_clones"),
    location_coverage="complete",
    extras=("files",),
))
register_adapter(AdapterDescriptor(
    "python_tests",
    ("run", "tests_pattern", "skipped_pattern", "budget_seconds"),
    _python_tests_spec,
    _runner("_run_python_tests"),
    produces_tests=True,
    budget=_spec_budget,
))
register_adapter(AdapterDescriptor(
    "elisp_tests",
    ("suite", "load_path", "emacs", "budget_seconds"),
    _elisp_tests_spec,
    _runner("_run_elisp_tests"),
    produces_tests=True,
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_compile",
    ("load_path", "emacs", "budget_seconds"),
    _elisp_lint_spec,
    _runner("_run_elisp_lint"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_checkdoc",
    ("load_path", "emacs", "budget_seconds"),
    _elisp_lint_spec,
    _runner("_run_elisp_lint"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "python_crap",
    ("requires", "threshold", "baseline"),
    _python_crap_spec,
    _runner("_run_python_crap"),
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="python_tests",
))
register_adapter(AdapterDescriptor(
    "elisp_crap",
    ("requires", "threshold", "baseline"),
    _elisp_crap_spec,
    _runner("_run_elisp_crap"),
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="elisp_tests",
))
register_adapter(AdapterDescriptor(
    "verification",
    ("requires", "baseline"),
    _verification_spec,
    _runner("_run_verification"),
    location_coverage="partial",
    directions={"executed": "min"},
    default_direction="max",
    requires_tests=True,
    entry_direction=_verification_entry_direction,
))
register_adapter(AdapterDescriptor(
    "owners",
    ("baseline", "rule"),
    _owners_spec,
    _runner("_run_owners"),
    location_coverage="complete",
    fixed_header=(1, "enforced", "max"),
))
