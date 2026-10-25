"""Gate identity, consumer revision, policy digest and the decision rule."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from .runner import RunResult, run


def _git(root: Path, args: list[str]) -> RunResult | None:
    command = [
        "git",
        "-c",
        f"safe.directory={root}",
        "-C",
        str(root),
        *args,
    ]
    result = run(command, budget_seconds=600, capture_limit=None)
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


def _obligation_entry(
    class_name: str,
    tier: int,
    class_def: Any,
    by_id: dict[str, Any],
    reasons: dict[tuple[str, int], str],
) -> dict[str, Any]:
    required = TIER_EVIDENCE[tier]
    entry: dict[str, Any] = {
        "class": class_name,
        "tier": tier,
        "status": "unsatisfied",
        "required": list(required),
        "checks": [],
        "reason": None,
    }
    if (class_name, tier) in reasons:
        entry["status"] = "exempted"
        entry["reason"] = reasons[(class_name, tier)]
        return entry
    counted = _counted_checks(class_def, by_id, required)
    entry["checks"] = counted
    if counted:
        entry["status"] = "satisfied"
    return entry


def obligations(config: Any, results: Iterable[Any]) -> list[dict[str, Any]]:
    """One assurance obligation per code class and required tier."""
    by_id = {result.id: result for result in results}
    reasons = {
        (entry.class_name, entry.tier): entry.reason
        for entry in config.not_applicable
    }
    tiers = sorted(set(config.required_tiers))
    return [
        _obligation_entry(
            class_name, tier, class_def, by_id, reasons
        )
        for class_name, class_def in config.classes.items()
        if class_def.code
        for tier in tiers
    ]


def _builtins_pass(results: list[Any]) -> bool:
    return all(
        result.is_satisfied()
        for result in results
        if result.kind in ("inventory", "hygiene")
    )


def _enforced_checks_pass(results: list[Any]) -> bool:
    return all(
        result.is_satisfied()
        for result in results
        if result.kind == "check" and result.enforcement == "enforced"
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


def decision(results: Iterable[Any], obligations: Iterable[Any]) -> str:
    results = list(results)
    if not (
        _builtins_pass(results)
        and _enforced_checks_pass(results)
        and all(item["status"] != "unsatisfied" for item in obligations)
    ):
        return "rejected"
    return "accepted_with_exceptions" if _has_exceptions(results) else "accepted"


def error_document(
    root: Path | None,
    policy: Path | None,
    message: str,
    *,
    prune: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": 2,
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
