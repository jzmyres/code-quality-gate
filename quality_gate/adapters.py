"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, its argument fields, location coverage, number display, subject
noun, failure wording and direction rule, whether it produces normalized test results, the baseline
extras it trusts, its baseline and budget handling, and its per-process setup.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from . import (
    clones, command, coverage_tool, elisp_crap, elisp_lint, elisp_tests, owners, python_crap, python_tests,
    ratchet, verification,
)
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    _number,
    _string,
)


def _default_budget(_spec: Any) -> int:
    from .checks import RATCHET_BUDGET_SECONDS

    return RATCHET_BUDGET_SECONDS


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
    run: Callable[[AdapterContext], Any]
    location_coverage: str = "none"
    display: Callable[[float], str] = ratchet._number
    subject_noun: str = ""
    failure_wording: str = "metric"
    default_direction: str | None = None
    extras: tuple[str, ...] = ()
    requires_adapter: str | None = None
    requires_tests: bool = False
    fixed_header: tuple[int, str, str] | None = None
    budget: Callable[[Any], int] = _default_budget
    entry_direction: Callable[[str, str], str] | None = None
    parse_candidate_inputs: bool = False
    argument_fields: tuple[str, ...] = ()
    no_tests_hint: str = ""
    process_setup: Callable[[], None] | None = None

    def allowed_keys(self) -> tuple[str, ...]:
        return (*COMMON_CHECK_KEYS, *self.keys)

    def arguments(self, spec: Any) -> Iterator[str]:
        """Yield command and path arguments from the declared spec fields."""
        for name in self.argument_fields:
            value = getattr(spec, name)
            if isinstance(value, str):
                yield value
            else:
                yield from value

    def direction_for_subject(self, subject: str, configured: str) -> str:
        if self.entry_direction is not None:
            return self.entry_direction(subject, configured)
        return self.default_direction or configured


def _baseline(raw: dict[str, Any], root: Path, path: Path, full_key: str) -> Path:
    name = _string(raw, "baseline", path, f"{full_key}.baseline")
    baseline = Path(name)
    if not baseline.is_absolute():
        baseline = root / baseline
    return baseline


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


def _spec_budget(spec: Any) -> int:
    return spec.budget_seconds


ADAPTERS: dict[str, AdapterDescriptor] = {}


def register_adapter(descriptor: AdapterDescriptor) -> AdapterDescriptor:
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


def setup_process() -> None:
    """Run the per-process setup declared by each registered adapter."""
    for descriptor in ADAPTERS.values():
        if descriptor.process_setup is not None:
            descriptor.process_setup()


register_adapter(AdapterDescriptor(
    "command",
    ("run", "budget_seconds", "must_match", "tests_pattern", "skipped_pattern"),
    command._command_spec,
    command._run_command,
    no_tests_hint=" (no tests_pattern)",
    argument_fields=("run",),
    budget=_spec_budget,
))
register_adapter(AdapterDescriptor(
    "clones",
    ("min_tokens", "baseline"),
    clones._clones_spec,
    clones._run_clones,
    location_coverage="complete",
    subject_noun="clone",
    failure_wording="occurrences",
    extras=("files",),
))
register_adapter(AdapterDescriptor(
    "python_tests",
    ("run", "tests_pattern", "skipped_pattern", "budget_seconds"),
    python_tests._python_tests_spec,
    python_tests._run_python_tests,
    process_setup=coverage_tool.install_worker_measurement,
    argument_fields=("run",),
    budget=_spec_budget,
))
register_adapter(AdapterDescriptor(
    "elisp_tests",
    ("suite", "load_path", "emacs", "budget_seconds"),
    elisp_tests._elisp_tests_spec,
    elisp_tests.run_tests,
    argument_fields=("emacs", "suite", "load_path"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_compile",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
    argument_fields=("emacs", "load_path"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_checkdoc",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
    argument_fields=("emacs", "load_path"),
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "python_crap",
    ("requires", "threshold", "baseline"),
    python_crap._python_crap_spec,
    python_crap._run_python_crap,
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="python_tests",
))
register_adapter(AdapterDescriptor(
    "elisp_crap",
    ("requires", "threshold", "baseline", "decision_rules"),
    elisp_crap._elisp_crap_spec,
    elisp_crap.run_crap,
    location_coverage="complete",
    display=lambda value: f"{value:.1f}",
    requires_adapter="elisp_tests",
))
register_adapter(AdapterDescriptor(
    "verification",
    ("requires", "baseline"),
    verification._verification_spec,
    verification._run_verification,
    location_coverage="partial",
    default_direction="max",
    requires_tests=True,
    entry_direction=verification._verification_entry_direction,
))
register_adapter(AdapterDescriptor(
    "owners",
    ("baseline", "rule"),
    owners._owners_spec,
    owners._run_owners,
    location_coverage="complete",
    fixed_header=(1, "enforced", "max"),
))
