"""Gate identity, consumer revision, policy digest and the decision rule."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Iterable


def _git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    command = [
        "git",
        "-c",
        f"safe.directory={root}",
        "-C",
        str(root),
        *args,
    ]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None


def gate_version() -> str:
    root = Path(__file__).resolve().parent.parent
    result = _git(root, ["rev-parse", "HEAD"])
    if result is None:
        return "unknown: cannot run git"
    if result.returncode != 0:
        detail = result.stderr.strip() or "git rev-parse failed"
        return f"unknown: {detail}"
    revision = result.stdout.strip()
    return revision or "unknown: git returned no revision"


def consumer_revision(root: Path) -> str | None:
    result = _git(root, ["rev-parse", "HEAD"])
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip() or None


def consumer_dirty(root: Path) -> bool | None:
    result = _git(root, ["status", "--porcelain"])
    if result is None or result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def policy_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def decision(
    inventory_code: int,
    hygiene_code: int,
    results: Iterable[Any],
) -> str:
    results = list(results)
    if inventory_code != 0 or hygiene_code != 0:
        return "rejected"
    enforced_failed = any(
        result.enforcement == "enforced" and result.outcome != "pass"
        for result in results
    )
    if enforced_failed:
        return "rejected"
    exceptions = any(
        result.enforcement == "advisory" and result.outcome != "pass"
        for result in results
    )
    if not exceptions:
        exceptions = any(
            result.ratchet is not None and result.ratchet.exceptions
            for result in results
        )
    return "accepted_with_exceptions" if exceptions else "accepted"


def error_document(
    root: Path | None, policy: Path | None, message: str
) -> dict[str, Any]:
    return {
        "schema": 1,
        "gate_version": gate_version(),
        "revision": consumer_revision(root) if root is not None else None,
        "dirty": consumer_dirty(root) if root is not None else None,
        "policy_sha256": policy_sha256(policy) if policy is not None else None,
        "decision": "error",
        "checks": [],
        "error": message,
    }
