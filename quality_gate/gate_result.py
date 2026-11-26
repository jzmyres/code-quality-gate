"""Gate identity, consumer revision, policy digest and the decision rule."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from .files import BUILTIN_RESULT_KINDS, git_argv
from .runner import RunResult, run


def _git(root: Path, args: list[str]) -> RunResult | None:
    result = run(
        git_argv(root, *args), budget_seconds=600, capture_limit=None
    )
    if result.execution == "error":
        return None
    return result


def _git_problem(result: RunResult | None, what: str) -> str | None:
    if result is None:
        return "unknown: cannot run git"
    if result.execution != "completed":
        return f"unknown: git {result.execution}"
    if result.returncode != 0:
        return f"unknown: {result.stderr_text.strip() or what}"
    return None


def gate_version() -> str:
    root = Path(__file__).resolve().parent.parent
    result = _git(root, ["rev-parse", "HEAD"])
    problem = _git_problem(result, "git rev-parse failed")
    if problem is not None:
        return problem
    assert result is not None
    revision = result.stdout_text.strip()
    return revision or "unknown: git returned no revision"


def consumer_revision(root: Path) -> str | None:
    result = _git(root, ["rev-parse", "HEAD"])
    if (
        result is None
        or result.execution != "completed"
        or result.returncode != 0
    ):
        return None
    return result.stdout_text.strip() or None


def consumer_dirty(root: Path) -> bool | None:
    result = _git(root, ["status", "--porcelain"])
    if (
        result is None
        or result.execution != "completed"
        or result.returncode != 0
    ):
        return None
    return bool(result.stdout_text.strip())


def policy_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


TIER_EVIDENCE: dict[int, tuple[str, ...]] = {
    1: ("tests",),
    2: ("properties", "fuzzing"),
    3: ("bounded",),
    4: ("proof",),
}


def _tests_counted(result: Any) -> bool:
    executed = (result.measurement or {}).get("tests")
    return isinstance(executed, int) and executed >= 1


def _evidence_matches(result: Any, required: tuple[str, ...]) -> bool:
    matching = [item for item in result.evidence if item in required]
    return bool(matching) and (
        "tests" not in matching or _tests_counted(result)
    )


def _counts_for(result: Any, required: tuple[str, ...]) -> bool:
    if result.kind != "check" or result.enforcement != "enforced":
        return False
    if not result.is_satisfied():
        return False
    return _evidence_matches(result, required)


def _counted_checks(
    class_def: Any,
    by_id: dict[str, Any],
    required: tuple[str, ...],
) -> list[str]:
    return [
        check_id
        for check_id in class_def.checks
        if (result := by_id.get(check_id)) is not None
        and _counts_for(result, required)
    ]


def _candidate_checks(
    class_def: Any,
    by_id: dict[str, Any],
    required: tuple[str, ...],
) -> list[str]:
    """The class's checks that declare the tier's required evidence."""
    return [
        check_id
        for check_id in class_def.checks
        if (result := by_id.get(check_id)) is not None
        and any(name in required for name in result.evidence)
    ]


def _unsatisfied(result: Any | None) -> bool:
    return result is not None and not result.is_satisfied()


def _root_causes(
    config: Any, identifier: str, by_id: dict[str, Any]
) -> list[str]:
    """The root check ids an unsatisfied check's failure comes from."""
    from .checks import _policy_order, _required

    roots: set[str] = set()
    for required in _required(config, config.checks[identifier]):
        if _unsatisfied(by_id.get(required)):
            roots.update(_root_causes(config, required, by_id))
    if not roots:
        return [identifier]
    return _policy_order(config, roots)


def _check_causes(
    config: Any, identifier: str, by_id: dict[str, Any]
) -> list[str] | None:
    """A check's root causes: ids for a consequence, null for a root."""
    if identifier == "module-contracts" and _unsatisfied(by_id.get("inventory")):
        return ["inventory"]
    if identifier not in config.checks:
        return None
    roots = _root_causes(config, identifier, by_id)
    return None if roots == [identifier] else roots


def check_causes(
    config: Any, results: Iterable[Any]
) -> dict[str, list[str] | None]:
    """Every check's caused_by value, null for a root or a satisfied entry."""
    by_id = {result.id: result for result in results}
    return {
        identifier: (
            _check_causes(config, identifier, by_id)
            if not result.is_satisfied()
            else None
        )
        for identifier, result in by_id.items()
    }


def _obligation_causes(
    config: Any,
    class_def: Any,
    by_id: dict[str, Any],
    required: tuple[str, ...],
) -> list[str] | None:
    """An unsatisfied obligation's root causes, or null when it is a policy gap."""
    from .checks import _policy_order

    roots: set[str] = set()
    for candidate in _candidate_checks(class_def, by_id, required):
        if by_id[candidate].is_satisfied():
            return None
        roots.update(_root_causes(config, candidate, by_id))
    return _policy_order(config, roots) or None


def _obligation_entry(
    config: Any,
    class_name: str,
    tier: int,
    class_def: Any,
    by_id: dict[str, Any],
    reasons: dict[tuple[str, int], str],
    *, partial: bool,
) -> dict[str, Any]:
    required = TIER_EVIDENCE[tier]
    entry: dict[str, Any] = {
        "class": class_name,
        "tier": tier,
        "status": "unsatisfied",
        "required": list(required),
        "checks": [],
        "caused_by": None,
        "reason": None,
    }
    if partial:
        entry.update(status="not_evaluated", reason="partial run")
        return entry
    if (class_name, tier) in reasons:
        entry["status"] = "exempted"
        entry["reason"] = reasons[(class_name, tier)]
        return entry
    counted = _counted_checks(class_def, by_id, required)
    entry["checks"] = counted
    if counted:
        entry["status"] = "satisfied"
        return entry
    entry["caused_by"] = _obligation_causes(
        config, class_def, by_id, required
    )
    return entry


def _obligation_inputs(
    config: Any, results: Iterable[Any], partial: bool,
) -> tuple[dict[str, Any], dict[tuple[str, int], str]]:
    if partial:
        return {}, {}
    by_id = {result.id: result for result in results}
    reasons = {
        (entry.class_name, entry.tier): entry.reason
        for entry in config.not_applicable
    }
    return by_id, reasons


def obligations(config: Any, results: Iterable[Any], *, partial: bool = False) -> list[dict[str, Any]]:
    """One assurance obligation per code class and required tier."""
    by_id, reasons = _obligation_inputs(config, results, partial)
    tiers = sorted(set(config.required_tiers))
    return [
        _obligation_entry(
            config, class_name, tier, class_def, by_id, reasons, partial=partial,
        )
        for class_name, class_def in config.classes.items()
        if class_def.code
        for tier in tiers
    ]


def _builtins_pass(results: list[Any]) -> bool:
    return all(
        result.is_satisfied()
        for result in results
        if result.kind in BUILTIN_RESULT_KINDS
    )


def _enforced_checks_pass(results: list[Any]) -> bool:
    return all(
        result.is_satisfied()
        for result in results
        if result.kind == "check"
        and result.enforcement == "enforced"
    )


def _advisory_failed(result: Any) -> bool:
    return (
        result.kind == "check"
        and result.enforcement == "advisory"
        and result.outcome != "pass"
    )


def _baseline_exception(result: Any) -> bool:
    return result.ratchet is not None and result.ratchet.exceptions


def _has_exceptions(results: list[Any]) -> bool:
    return any(
        _advisory_failed(result) or _baseline_exception(result)
        for result in results
    )


def _run_passes(results: list[Any], obligations: Iterable[Any]) -> bool:
    return (
        _builtins_pass(results)
        and _enforced_checks_pass(results)
        and all(item["status"] != "unsatisfied" for item in obligations)
    )


def decision(
    results: Iterable[Any],
    obligations: Iterable[Any],
    *,
    partial: bool = False,
) -> str:
    results = list(results)
    if not _run_passes(results, [] if partial else obligations):
        return "rejected"
    if partial:
        return "partial"
    return "accepted_with_exceptions" if _has_exceptions(results) else "accepted"


def error_document(
    root: Path | None,
    policy: Path | None,
    message: str,
    *,
    prune: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": 3,
        "gate_version": gate_version(),
        "revision": consumer_revision(root) if root is not None else None,
        "dirty": consumer_dirty(root) if root is not None else None,
        "policy_sha256": policy_sha256(policy) if policy is not None else None,
        "decision": "error",
        "checks": [],
        "obligations": [],
        "prune": prune
        or {"requested": [], "performed": False, "reason": None},
        "error": message,
    }
