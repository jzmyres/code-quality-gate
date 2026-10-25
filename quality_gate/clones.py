"""jscpd invocation, SARIF parsing and clone measurement."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .files import validate_inventory
from .policy import Config, GateError
from .ratchet import Finding, pruned_entries, write_baseline
from .tools import _jscpd_binary


@dataclass(frozen=True)
class Clone:
    fingerprint: str
    locations: tuple[str, ...]


def _sarif_path(uri: str, root: Path) -> str:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme == "file":
        path = Path(urllib.parse.unquote(parsed.path))
        try:
            path = path.relative_to(root)
        except ValueError:
            pass
        return str(path)
    path = urllib.parse.unquote(uri)
    while path.startswith("./"):
        path = path[2:]
    absolute = Path(path)
    if absolute.is_absolute():
        try:
            return str(absolute.relative_to(root))
        except ValueError:
            return path
    return path


def _sarif_location(location: dict[str, Any], root: Path, where: str) -> str:
    try:
        physical = location["physicalLocation"]
        artifact = physical["artifactLocation"]
        uri = artifact["uri"]
        region = physical.get("region", {})
    except (KeyError, TypeError) as error:
        raise GateError(f"malformed SARIF at {where}: missing location data") from error
    if not isinstance(uri, str):
        raise GateError(f"malformed SARIF at {where}: location uri is not a string")
    if not isinstance(region, dict):
        raise GateError(f"malformed SARIF at {where}: region is not an object")
    start = region.get("startLine")
    end = region.get("endLine", start)
    if isinstance(start, bool) or not isinstance(start, int):
        raise GateError(f"malformed SARIF at {where}: startLine is not an integer")
    if end is None:
        end = start
    if isinstance(end, bool) or not isinstance(end, int):
        raise GateError(f"malformed SARIF at {where}: endLine is not an integer")
    path = _sarif_path(uri, root)
    if start == end:
        return f"{path}:{start}"
    return f"{path}:{start}-{end}"


def _parse_sarif(report: Path, root: Path) -> list[Clone]:
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except OSError as error:
        raise GateError(f"cannot read SARIF report {report}: {error}") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GateError(f"invalid SARIF report {report}: {error}") from error
    if not isinstance(data, dict):
        raise GateError(f"invalid SARIF report {report}: expected a JSON object")
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise GateError(f"invalid SARIF report {report}: expected a runs list")
    clones: list[Clone] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise GateError(
                f"invalid SARIF report {report}: runs[{run_index}] is not an object"
            )
        results = run.get("results", [])
        if not isinstance(results, list):
            raise GateError(
                f"invalid SARIF report {report}: "
                f"runs[{run_index}].results is not a list"
            )
        for result_index, result in enumerate(results):
            where = f"runs[{run_index}].results[{result_index}]"
            if not isinstance(result, dict):
                raise GateError(
                    f"invalid SARIF report {report}: {where} is not an object"
                )
            fingerprints = result.get("partialFingerprints")
            fingerprint = (
                fingerprints.get("jscpdCloneHash/v1")
                if isinstance(fingerprints, dict)
                else None
            )
            if not isinstance(fingerprint, str) or not fingerprint:
                raise GateError(
                    f"invalid SARIF report {report}: {where} has no "
                    'partialFingerprints["jscpdCloneHash/v1"]'
                )
            locations = result.get("locations", [])
            related = result.get("relatedLocations", [])
            if not isinstance(locations, list) or not isinstance(related, list):
                raise GateError(
                    f"invalid SARIF report {report}: "
                    f"{where} has malformed locations"
                )
            formatted: list[str] = []
            seen: set[str] = set()
            for location in [*locations, *related]:
                if not isinstance(location, dict):
                    raise GateError(
                        f"invalid SARIF report {report}: "
                        f"{where} has a non-object location"
                    )
                text = _sarif_location(location, root, where)
                if text not in seen:
                    seen.add(text)
                    formatted.append(text)
            if not formatted:
                raise GateError(
                    f"invalid SARIF report {report}: {where} has no locations"
                )
            clones.append(Clone(fingerprint, tuple(formatted)))
    return clones


def _run_jscpd(
    root: Path, binary: Path, files: list[str], min_tokens: int
) -> list[Clone]:
    with tempfile.TemporaryDirectory(prefix="qg-clones-") as temporary:
        output = Path(temporary)
        command = [
            str(binary),
            "--min-tokens",
            str(min_tokens),
            "--reporters",
            "sarif",
            "--output",
            str(output),
            "--fail-on-empty",
            "--no-tips",
            "--no-colors",
            "--",
            *files,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
        except subprocess.TimeoutExpired as error:
            raise GateError(f"jscpd exceeded its 600 second budget: {error}") from error
        except OSError as error:
            raise GateError(f"cannot run jscpd at {binary}: {error}") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise GateError(
                f"jscpd failed (exit {result.returncode}): "
                f"{detail or 'no output'}"
            )
        report = output / "jscpd-report.sarif"
        if not report.is_file():
            raise GateError(f"jscpd wrote no report at {report}")
        return _parse_sarif(report, root)


def measure_clones(
    root: Path, files: list[str], min_tokens: int
) -> list[Finding]:
    binary = _jscpd_binary()
    clones = _run_jscpd(root, binary, files, min_tokens)
    occurrences: dict[str, list[Clone]] = {}
    for clone in clones:
        occurrences.setdefault(clone.fingerprint, []).append(clone)
    findings: list[Finding] = []
    for fingerprint in sorted(occurrences):
        actual = occurrences[fingerprint]
        locations = "; ".join(
            location for clone in actual for location in clone.locations
        )
        findings.append(Finding(fingerprint, len(actual), locations))
    return findings


def command_clones(root: Path, config: Config, prune: bool = False) -> int:
    clone_checks = [
        check for check in config.checks.values() if check.adapter == "clones"
    ]
    if not clone_checks:
        print(
            f"clones: no check with adapter 'clones' is configured in "
            f"{config.path}",
            file=sys.stderr,
        )
        return 2
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        print(f"clones: {error}", file=sys.stderr)
        return 1
    if violations:
        for violation in violations:
            print(f"clones: inventory: {violation}", file=sys.stderr)
        return 1

    from .checks import run_check

    failed = False
    refused = False
    for check in clone_checks:
        result = run_check(
            root, config, check, files, classes, prefix="clones"
        )
        if result.outcome != "pass":
            failed = True
            if prune:
                print(
                    f"clones: prune refused because check {check.id} "
                    "did not pass; nothing written",
                    file=sys.stderr,
                )
                refused = True
            continue
        if not prune:
            continue
        assert check.baseline is not None
        existed = check.baseline.exists()
        try:
            write_baseline(check.baseline, pruned_entries(result.ratchet))
        except GateError as error:
            print(f"clones: {error}", file=sys.stderr)
            failed = True
            continue
        if check.baseline.exists():
            print(f"clones: baseline updated at {check.baseline}")
        elif existed:
            print(f"clones: baseline removed at {check.baseline}")
    if failed or refused:
        return 1
    return 0
