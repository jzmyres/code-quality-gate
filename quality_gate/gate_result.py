"""Gate identity, consumer revision, policy digest and the decision rule."""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from .files import BUILTIN_RESULT_KINDS, DiffBaseOverride, _verified_commit, git_argv
from .policy import UsageError
from .ratchet import FindingResult
from .runner import RunResult, run

if TYPE_CHECKING:
    from .checks import CheckResult


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


def _successful_probe(root: Path, args: list[str]) -> RunResult | None:
    result = _git(root, args)
    return result if _git_problem(result, "") is None else None


def _consumer_head(root: Path) -> str | None:
    head = _successful_probe(root, ["rev-parse", "HEAD"])
    if head is None:
        return None
    return head.stdout_text.strip() or None


def _index_supports_clean_status(root: Path) -> bool:
    index = _successful_probe(root, ["ls-files", "-v", "-z"])
    if index is None:
        return False
    flags = (entry[:1] for entry in index.stdout.split(b"\0"))
    return not any(flag == b"S" or flag.islower() for flag in flags)


def _consumer_dirty(root: Path, options: list[str]) -> bool | None:
    status = _successful_probe(root, ["status", "--porcelain", *options])
    if status is None:
        return None
    if status.stdout_text.strip():
        return True
    if options and not _index_supports_clean_status(root):
        return None
    return False


def consumer_identity(root: Path, *, strict: bool = False) -> dict[str, Any]:
    if strict:
        revision, _ = _verified_commit(root, "HEAD")
        options = ["--untracked-files=all", "--ignore-submodules=none"]
    else:
        revision = _consumer_head(root)
        options = []
    return {"revision": revision, "dirty": _consumer_dirty(root, options)}


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
    loaded_digest: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": 3,
        "gate_version": gate_version(),
        **(consumer_identity(root) if root is not None else {"revision": None, "dirty": None}),
        "policy_sha256": loaded_digest if loaded_digest is not None else (
            policy_sha256(policy) if policy is not None else None
        ),
        "decision": "error",
        "checks": [],
        "obligations": [],
        "prune": prune
        or {"requested": [], "performed": False, "reason": None},
        "error": message,
    }


def _write_record(fd: int, line: bytes) -> None:
    if os.write(fd, line) != len(line):
        raise OSError(errno.EIO, "short ledger write")


def _open_ledger(path: Path) -> int:
    return os.open(path, os.O_RDWR | os.O_APPEND | os.O_NONBLOCK)


def _append_record(fd: int, line: bytes) -> None:
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "ledger destination must be a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            raise OSError(errno.EINVAL, "ledger ends with an incomplete record")
        _write_record(fd, line)
    finally:
        os.close(fd)


def _publish_first_record(path: Path, line: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".qg-ledger-") as temporary:
        _write_record(temporary.fileno(), line)
        try:
            os.link(temporary.name, path)
        except FileExistsError:
            _append_record(_open_ledger(path), line)


def _publish_record(path: Path, line: bytes) -> None:
    try:
        fd = _open_ledger(path)
    except FileNotFoundError:
        _publish_first_record(path, line)
    else:
        _append_record(fd, line)


def append_ledger(path: Path, supplied: str, record: dict[str, Any]) -> None:
    line = (json.dumps(record, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    try:
        _publish_record(path, line)
    except OSError as error:
        raise UsageError(f"check: cannot write the gate ledger to {supplied}: {error}") from error


_FINDING_IDENTITY_FIELDS = ("rule", "name")
_FINDING_FIELDS = (
    "subject", *_FINDING_IDENTITY_FIELDS, "module", "key", "pattern", "owners", "source_module",
    "target_module", "failed_conditions", "permitted_entry_points", "capability", "owner", "modules",
    "protected_path", "stage", "kind", "access",
)
_EDGE_FIELDS = ("source", "target", "line", "kind")
_MEASUREMENT_FIELDS = (
    "path", "file", "line", "column", "codepoint", "byte_offset", "cc", "statements", "executed",
    "excluded_lines", "points", "hits", *_FINDING_IDENTITY_FIELDS, "component", "call_sites", "direct_test",
    "caller", "helper", "helper_file", "helper_name", "cc_before", "cc_after", "function", "operator",
    "outcome", "tests", "literals", "first", "second", "similarity", "min_tokens", "max_tokens",
    "callee", "forwarded", "constants", "chain_depth", "chain", "longest", "ratio", "tokens",
)


def _fields(data: dict[str, Any], names: Iterable[str]) -> dict[str, Any]:
    return {key: data[key] for key in names if key in data}


_MEASUREMENT_SEQUENCES = {
    "cycle": _EDGE_FIELDS,
    "occurrences": ("path", "line", "column", "codepoint"),
    "owners": ("path", "line", "name", "kind", "literals"),
}


def _measurement_sequences(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: [_fields(row, fields) for row in data[key]]
        for key, fields in _MEASUREMENT_SEQUENCES.items() if key in data
    }


def _measurement_values(data: dict[str, Any]) -> dict[str, Any]:
    projected = _fields(data, _MEASUREMENT_FIELDS)
    if "edge" in data:
        projected["edge"] = _fields(data["edge"], _EDGE_FIELDS)
    if "limit" in data:
        limit = data["limit"]
        projected["limit"] = (
            _fields(limit, ("min_tokens", "max_tokens", "similarity")) if isinstance(limit, dict) else limit
        )
    return projected


def _range(path: str, start: int | None, end: int | None) -> dict[str, Any]:
    return {"path": path, "start_line": start, "end_line": end}


def _ratchet_finding(finding: FindingResult) -> dict[str, Any]:
    expiry = finding.baseline_expires
    row = {
        "subject": finding.subject,
        "value": finding.value,
        "bound": finding.bound,
        "threshold": finding.threshold,
        "covered_by_baseline": finding.covered_by_baseline,
        "blocking": finding.blocking,
        "expired": finding.expired,
        "baseline_expires": expiry.isoformat() if expiry else None,
        "locations": None,
    }
    if finding.locations is None:
        row["location"] = finding.location
    else:
        row["locations"] = [_range(item.path, item.start_line, item.end_line) for item in finding.locations]
    if finding.measurement is not None:
        row["measurement"] = {
            **_measurement_values(finding.measurement),
            **_measurement_sequences(finding.measurement),
        }
    return row


def _finding_locations(
    finding: dict[str, Any], edge: dict[str, Any],
) -> list[dict[str, Any]] | None:
    locations = finding.get("locations")
    if locations is not None:
        return [_range(loc["path"], loc.get("start_line"), loc.get("end_line")) for loc in locations]
    path = finding.get("file") or finding.get("path") or edge.get("source")
    if path is None:
        return None
    line = finding.get("line", edge.get("line"))
    return [_range(path, line, line)]


def _ledger_finding(finding: FindingResult | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, FindingResult):
        return _ratchet_finding(finding)
    row = _fields(finding, _FINDING_FIELDS)
    edge = finding.get("edge") or {}
    if edge:
        row["edge"] = _fields(edge, _EDGE_FIELDS)
    row["locations"] = _finding_locations(finding, edge)
    if row["locations"] is None:
        row.update(_fields(finding, ("location",)))
    return row


def _reported_findings(result: CheckResult) -> list[Any]:
    if result.adapter in ("comments", "env_surface") and result.measurement is not None:
        return [*result.findings, *result.measurement["findings"]]
    return result.findings


def _check_base(result: CheckResult) -> str | None:
    if result.resolved_base is not None:
        return result.resolved_base
    reported = (result.measurement or {}).get("base")
    return reported.get("commit") if isinstance(reported, dict) else None


def _ledger_check(result: CheckResult) -> dict[str, Any]:
    selection = result.report_fields.get("selection")
    row = {
        "id": result.id,
        "adapter": result.adapter,
        "metric_version": result.metric_version,
        "execution": result.execution,
        "outcome": result.outcome,
        "duration_seconds": round(result.duration_seconds, 6),
        "satisfied": result.is_satisfied(),
        "enforcement": result.enforcement,
        "location_coverage": result._location_coverage(),
        "resolved_baseline_entries": result.resolved_baseline_entries,
        "unmeasured_baseline_entries": result.unmeasured_baseline_entries,
        "resolved_base": _check_base(result),
        "selection": None if selection is None else {
            key: list(selection[key]) for key in ("selected", "left_out")
        },
        "findings": [_ledger_finding(item) for item in _reported_findings(result)],
    }

    if "test_results" in result.report_fields:
        row["test_results"] = result.report_fields["test_results"]
    return row


def _ledger_scope(
    selected: list[str] | None, base: str | None, diff: DiffBaseOverride,
) -> dict[str, Any]:
    changed = diff.changed_paths
    return {
        "scope": "affected" if base is not None else "partial" if selected is not None else "full",
        "selected": selected,
        "base": base,
        "resolved_base": diff.base.commit if diff.base is not None else None,
        "changed_paths": sorted(changed) if changed is not None else None,
    }


def _exemptions(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _fields(item, ("class", "tier")) for item in document.get("obligations", ())
        if item["status"] == "exempted"
    ]


def ledger_record(
    *, run_id: str, start: dict[str, Any], end: dict[str, Any], version: str, digest: str,
    selected: list[str] | None, base: str | None, diff: DiffBaseOverride, results: list[CheckResult],
    interrupted: dict[str, Any] | None, document: dict[str, Any], status: int | None,
    termination: str | None,
) -> dict[str, Any]:
    attributable = start == end and start["dirty"] is False
    rows = [_ledger_check(result) for result in results]
    if interrupted is not None:
        rows.append(interrupted)
    return {
        "schema": 1,
        "run_id": run_id,
        "gate_version": version,
        "policy_sha256": digest,
        "start": start,
        "end": end,
        "attribution_revision": start["revision"] if attributable else None,
        **_ledger_scope(selected, base, diff),
        "decision": document["decision"] if termination is None else "error",
        "exit_status": status,
        "complete": termination is None,
        "termination": termination,
        "checks": rows,
        "exemptions": _exemptions(document),
    }
