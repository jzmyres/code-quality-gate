"""jscpd invocation, SARIF parsing and clone measurement."""
from __future__ import annotations

import json
import sys
import tempfile
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .files import validate_inventory
from .policy import (
    DEFAULT_MAX_BYTES,
    Config,
    GateError,
    UnsupportedError,
)
from .ratchet import Finding, pruned_entries, write_baseline
from .runner import Diagnostics, run
from .tools import _jscpd_binary


FORMAT_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "jsx",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c-header",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
    ".el": "lisp",
    ".lisp": "lisp",
    ".clj": "clojure",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".lua": "lua",
    ".pl": "perl",
    ".r": "r",
    ".sql": "sql",
    ".md": "markdown",
    ".json": "json",
}


def _no_completed(report: Path, detail: str) -> UnsupportedError:
    return UnsupportedError(
        f"no completed jscpd run: {report}: {detail}"
    )


def _read_report(report: Path) -> Any:
    try:
        return json.loads(report.read_text(encoding="utf-8"))
    except OSError as error:
        raise _no_completed(report, f"cannot read report: {error}") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise _no_completed(report, f"invalid JSON: {error}") from error


class CloneEvidenceError(UnsupportedError):
    """A jscpd run did not produce complete clone evidence."""

    def __init__(
        self,
        message: str,
        *,
        diagnostics: Diagnostics | None = None,
        execution: str = "completed",
    ) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics
        self.execution = execution


@dataclass
class CloneMeasurement:
    findings: list[Finding]
    diagnostics: Diagnostics
    execution: str
    error: str | None = None
    unsupported: bool = False


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


def _sarif_location(
    location: dict[str, Any], root: Path, where: str, report: Path
) -> str:
    try:
        physical = location["physicalLocation"]
        artifact = physical["artifactLocation"]
        uri = artifact["uri"]
        region = physical.get("region", {})
    except (KeyError, TypeError) as error:
        raise _no_completed(
            report, f"{where}: missing location data"
        ) from error
    if not isinstance(physical, dict) or not isinstance(artifact, dict):
        raise _no_completed(report, f"{where}: location is not an object")
    if not isinstance(uri, str):
        raise _no_completed(report, f"{where}: location uri is not a string")
    if not isinstance(region, dict):
        raise _no_completed(report, f"{where}: region is not an object")
    start = region.get("startLine")
    end = region.get("endLine", start)
    if isinstance(start, bool) or not isinstance(start, int):
        raise _no_completed(
            report, f"{where}: startLine is not an integer"
        )
    if end is None:
        end = start
    if isinstance(end, bool) or not isinstance(end, int):
        raise _no_completed(
            report, f"{where}: endLine is not an integer"
        )
    path = _sarif_path(uri, root)
    if start == end:
        return f"{path}:{start}"
    return f"{path}:{start}-{end}"


def _parse_sarif(report: Path, root: Path) -> list[Clone]:
    data = _read_report(report)
    if not isinstance(data, dict):
        raise _no_completed(report, "expected a JSON object")
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise _no_completed(report, "expected exactly one run")
    run = runs[0]
    if not isinstance(run, dict):
        raise _no_completed(report, "runs[0] is not an object")
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if (
        not isinstance(driver, dict)
        or driver.get("name") != "jscpd"
    ):
        raise _no_completed(report, "run was not produced by jscpd")
    results = run.get("results")
    if not isinstance(results, list):
        raise _no_completed(report, "runs[0].results is not a list")
    clones: list[Clone] = []
    for result_index, result in enumerate(results):
        where = f"runs[0].results[{result_index}]"
        if not isinstance(result, dict):
            raise _no_completed(report, f"{where} is not an object")
        fingerprints = result.get("partialFingerprints")
        fingerprint = (
            fingerprints.get("jscpdCloneHash/v1")
            if isinstance(fingerprints, dict)
            else None
        )
        if not isinstance(fingerprint, str) or not fingerprint:
            raise _no_completed(
                report,
                f"{where} has no "
                'partialFingerprints["jscpdCloneHash/v1"]',
            )
        locations = result.get("locations")
        related = result.get("relatedLocations", [])
        if not isinstance(locations, list) or not isinstance(related, list):
            raise _no_completed(
                report, f"{where} has malformed locations"
            )
        formatted: list[str] = []
        seen: set[str] = set()
        for location in [*locations, *related]:
            if not isinstance(location, dict):
                raise _no_completed(
                    report, f"{where} has a non-object location"
                )
            text = _sarif_location(location, root, where, report)
            if text not in seen:
                seen.add(text)
                formatted.append(text)
        if not formatted:
            raise _no_completed(report, f"{where} has no locations")
        clones.append(Clone(fingerprint, tuple(formatted)))
    return clones


def _selected_skipped(files: list[str], data: dict[str, Any]) -> list[str]:
    statistics = data.get("statistics")
    if not isinstance(statistics, dict):
        return list(files)
    formats = statistics.get("formats")
    if not isinstance(formats, dict):
        return list(files)
    analyzed: dict[str, int] = {}
    for name, raw in formats.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            return list(files)
        sources = raw.get("sources")
        if isinstance(sources, bool) or not isinstance(sources, int):
            return list(files)
        analyzed[name] = sources
    selected = Counter(Path(name).suffix.lower() for name in files)
    candidates: set[str] = set()
    for suffix, count in selected.items():
        format_name = FORMAT_BY_SUFFIX.get(suffix)
        if (
            format_name is None
            or analyzed.get(format_name, 0) < count
        ):
            candidates.update(
                name
                for name in files
                if Path(name).suffix.lower() == suffix
            )
    if not candidates:
        candidates.update(files)
    return sorted(candidates)


def _parse_jscpd_json(report: Path, files: list[str]) -> None:
    data = _read_report(report)
    if not isinstance(data, dict):
        raise _no_completed(report, "expected a JSON object")
    statistics = data.get("statistics")
    if not isinstance(statistics, dict):
        raise _no_completed(report, "statistics is not an object")
    total = statistics.get("total")
    if not isinstance(total, dict):
        raise _no_completed(report, "statistics.total is not an object")
    sources = total.get("sources")
    if isinstance(sources, bool) or not isinstance(sources, int):
        raise _no_completed(
            report, "statistics.total.sources is not an integer"
        )
    if sources != len(files):
        skipped = _selected_skipped(files, data)
        raise _no_completed(
            report,
            f"analysed {sources} of {len(files)} selected files; "
            f"not analysed: {', '.join(skipped)}",
        )


def _jscpd_command(
    binary: Path,
    files: list[str],
    min_tokens: int,
    max_bytes: int,
    output: Path,
    config: Path,
) -> list[str]:
    formats = {
        FORMAT_BY_SUFFIX.get(Path(name).suffix.lower()) for name in files
    }
    command = [
        str(binary),
        "--config",
        str(config),
        "--min-tokens",
        str(min_tokens),
        "--min-lines",
        "5",
        "--max-size",
        str(max_bytes),
        "--ignore",
        ".qg-never-match",
        "--no-gitignore",
        "--mode",
        "mild",
    ]
    if None not in formats:
        command.extend(["--format", ",".join(sorted(formats))])
    command.extend(
        [
            "--reporters",
            "json,sarif",
            "--output",
            str(output),
            "--fail-on-empty",
            "--no-tips",
            "--no-colors",
            "--",
            *files,
        ]
    )
    return command


def _raise_jscpd_termination(
    result: Any, diagnostics: Diagnostics
) -> None:
    if result.execution == "error":
        raise CloneEvidenceError(
            f"cannot run jscpd: {result.error}",
            diagnostics=diagnostics,
            execution="error",
        )
    if result.execution == "budget":
        raise CloneEvidenceError(
            "jscpd exceeded its 600 second budget",
            diagnostics=diagnostics,
            execution="budget",
        )
    if result.execution == "signal":
        raise CloneEvidenceError(
            f"jscpd terminated by signal {-result.returncode}",
            diagnostics=diagnostics,
            execution="signal",
        )


def _raise_jscpd_failure(result: Any, diagnostics: Diagnostics) -> None:
    _raise_jscpd_termination(result, diagnostics)
    if result.returncode != 0:
        detail = result.stderr_text.strip() or result.stdout_text.strip()
        raise CloneEvidenceError(
            f"jscpd failed (exit {result.returncode}): "
            f"{detail or 'no output'}",
            diagnostics=diagnostics,
        )


def _run_jscpd(
    root: Path,
    binary: Path,
    files: list[str],
    min_tokens: int,
    max_bytes: int,
) -> tuple[list[Clone], Diagnostics, str]:
    with tempfile.TemporaryDirectory(prefix="qg-clones-") as temporary:
        output = Path(temporary)
        config = output / "jscpd-config.json"
        config.write_text("{}", encoding="utf-8")
        command = _jscpd_command(
            binary, files, min_tokens, max_bytes, output, config
        )
        result = run(command, cwd=root, budget_seconds=600)
        diagnostics = result.diagnostics()
        _raise_jscpd_failure(result, diagnostics)
        sarif = output / "jscpd-report.sarif"
        json_report = output / "jscpd-report.json"
        if not sarif.is_file() or not json_report.is_file():
            raise CloneEvidenceError(
                f"jscpd wrote no report at {sarif} or {json_report}",
                diagnostics=diagnostics,
            )
        try:
            _parse_jscpd_json(json_report, files)
            clones = _parse_sarif(sarif, root)
        except UnsupportedError as error:
            raise CloneEvidenceError(
                str(error),
                diagnostics=diagnostics,
            ) from error
        return clones, diagnostics, result.execution


def _clone_findings(clones: list[Clone]) -> list[Finding]:
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


def measure_clones(
    root: Path,
    files: list[str],
    min_tokens: int,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> CloneMeasurement:
    try:
        binary = _jscpd_binary()
    except UnsupportedError as error:
        return CloneMeasurement([], Diagnostics(), "error", str(error), True)
    try:
        clones, diagnostics, execution = _run_jscpd(
            root, binary, files, min_tokens, max_bytes
        )
    except CloneEvidenceError as error:
        return CloneMeasurement(
            [],
            error.diagnostics or Diagnostics(),
            error.execution,
            str(error),
            True,
        )
    except GateError as error:
        return CloneMeasurement([], Diagnostics(), "error", str(error), False)
    return CloneMeasurement(
        _clone_findings(clones), diagnostics, execution
    )


def _prune_clone(check: Any, result: Any) -> tuple[bool, bool]:
    assert check.baseline is not None
    if result.ratchet is None:
        print(
            f"clones: prune refused because check {check.id} produced "
            "no ratchet result; nothing written",
            file=sys.stderr,
        )
        return False, True
    existed = check.baseline.exists()
    try:
        write_baseline(
            check.baseline,
            pruned_entries(result.ratchet),
            check_id=check.id,
            metric_version=check.metric_version,
        )
    except GateError as error:
        print(f"clones: {error}", file=sys.stderr)
        return True, False
    if check.baseline.exists():
        print(f"clones: baseline updated at {check.baseline}")
    elif existed:
        print(f"clones: baseline removed at {check.baseline}")
    return False, False


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
        if not result.is_satisfied():
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
        write_failed, write_refused = _prune_clone(check, result)
        failed = failed or write_failed
        refused = refused or write_refused
    if failed or refused:
        return 1
    return 0
