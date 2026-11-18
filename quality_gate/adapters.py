"""The adapter descriptor registry: one declaration per adapter.

Every adapter's identity lives here exactly once: the configuration keys it
accepts, its parser, its runner, location coverage, number display, subject
noun, failure wording and direction rule, whether it produces test counts, the baseline
extras it trusts, its baseline and budget handling, and its per-process setup.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import (
    clones, command, elisp_crap, elisp_lint, elisp_tests, python_crap, python_mutation,
    python_shape, python_tests, ratchet, source_chars, variant_dispatch, verification,
)
from .files import DiffBaseOverride
from .policy import (
    COMMON_CHECK_KEYS,
    DEFAULT_CRAP_THRESHOLD,
    _config_error,
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
    evidence_dir: Path
    base_override: DiffBaseOverride | None = None


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
    budget: Callable[[Any], int] = _default_budget
    entry_direction: Callable[[str, str], str] | None = None
    parse_candidate_inputs: bool = False
    no_tests_hint: str = ""

    def allowed_keys(self) -> tuple[str, ...]:
        return (*COMMON_CHECK_KEYS, *self.keys)

    def direction_for_subject(self, subject: str, configured: str) -> str:
        if self.entry_direction is not None:
            return self.entry_direction(subject, configured)
        return self.default_direction or configured

    def required_checks(
        self, requires: str | None, earlier: list[Any]
    ) -> tuple[str, ...]:
        """The earlier check ids a check of this adapter depends on."""
        from .checks import _test_check_dependencies

        if not self.requires_tests:
            return () if requires is None else (requires,)
        return (
            *_test_check_dependencies(requires, earlier),
            *(check.id for check in earlier if check.adapter == "python_crap"),
        )


def _baseline(
    raw: dict[str, Any], root: Path, path: Path, full_key: str
) -> Path | None:
    if "baseline" not in raw:
        return None
    name = _string(raw, "baseline", path, f"{full_key}.baseline")
    if "\x00" in name:
        raise _config_error(
            path, f"{full_key}.baseline", "a path without NUL", repr(name)
        )
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


register_adapter(AdapterDescriptor(
    "command",
    ("run", "budget_seconds", "must_match", "tests_pattern", "skipped_pattern"),
    command._command_spec,
    command._run_command,
    no_tests_hint=" (no tests_pattern)",
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
    "source_chars",
    ("scope", "base", "include_untracked", "allow", "deny", "baseline"),
    source_chars._source_chars_spec,
    source_chars._run_source_chars,
    location_coverage="complete",
    subject_noun="character",
    failure_wording="occurrences",
))
register_adapter(AdapterDescriptor(
    "python_tests",
    ("run", "tests_pattern", "skipped_pattern", "budget_seconds", "workers"),
    python_tests._python_tests_spec,
    python_tests._run_python_tests,
    budget=_spec_budget,
))
register_adapter(AdapterDescriptor(
    "elisp_tests",
    ("suite", "load_path", "emacs", "budget_seconds"),
    elisp_tests._elisp_tests_spec,
    elisp_tests.run_tests,
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_compile",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
    budget=_spec_budget,
    parse_candidate_inputs=True,
))
register_adapter(AdapterDescriptor(
    "elisp_checkdoc",
    ("load_path", "emacs", "budget_seconds"),
    elisp_lint._elisp_lint_spec,
    elisp_lint.run_lint,
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
    "python_shape",
    (
        "scope", "base", "max_chain", "clone_min_tokens", "clone_similarity",
        "crap_check",
    ),
    python_shape._python_shape_spec,
    python_shape._run_python_shape,
    location_coverage="complete",
))
register_adapter(AdapterDescriptor(
    "python_mutation",
    ("scope", "base", "mutant_seconds", "function_mutants", "run_seconds"),
    python_mutation._python_mutation_spec,
    python_mutation._run_python_mutation,
    location_coverage="complete",
    budget=python_mutation._budget,
))
register_adapter(AdapterDescriptor(
    "variant_dispatch",
    ("scope", "base"),
    variant_dispatch._variant_dispatch_spec,
    variant_dispatch._run_variant_dispatch,
    location_coverage="complete",
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
