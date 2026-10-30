"""jscpd invocation, SARIF parsing and clone measurement."""
from __future__ import annotations

import json
import tempfile
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import (
    DEFAULT_MAX_BYTES,
    GateError,
    UnsupportedError,
)
from .ratchet import Finding, Location
from .runner import (
    Diagnostics,
    analysis_step,
    mark_step,
    record_diagnostics,
    remaining_budget,
    run,
)
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


def _required_object(
    value: object, report: Path, message: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _no_completed(report, message)
    return value


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
    locations: tuple[Location, ...]
    complete: bool


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


def _sarif_fields(
    location: dict[str, Any], where: str, report: Path
) -> tuple[Any, Any, Any, Any]:
    try:
        physical = location["physicalLocation"]
        artifact = physical["artifactLocation"]
        uri = artifact["uri"]
        region = physical.get("region", {})
    except (KeyError, TypeError) as error:
        raise _no_completed(
            report, f"{where}: missing location data"
        ) from error
    return physical, artifact, uri, region


def _validate_sarif_fields(
    physical: Any, artifact: Any, uri: Any, region: Any, where: str, report: Path
) -> None:
    if not isinstance(physical, dict) or not isinstance(artifact, dict):
        raise _no_completed(report, f"{where}: location is not an object")
    if not isinstance(uri, str):
        raise _no_completed(report, f"{where}: location uri is not a string")
    if not isinstance(region, dict):
        raise _no_completed(report, f"{where}: region is not an object")


def _sarif_integer(value: Any, name: str, where: str, report: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _no_completed(report, f"{where}: {name} is not an integer")
    return value


def _sarif_lines(region: dict[str, Any], where: str, report: Path) -> tuple[int, int]:
    start = _sarif_integer(region.get("startLine"), "startLine", where, report)
    end = region.get("endLine", start)
    if end is None:
        end = start
    return start, _sarif_integer(end, "endLine", where, report)


def _sarif_range(
    location: dict[str, Any], root: Path, where: str, report: Path
) -> Location:
    physical, artifact, uri, region = _sarif_fields(location, where, report)
    _validate_sarif_fields(physical, artifact, uri, region, where, report)
    start, end = _sarif_lines(region, where, report)
    return Location(_sarif_path(uri, root), start, end)


def _sarif_location(
    location: dict[str, Any], root: Path, where: str, report: Path
) -> str:
    return str(_sarif_range(location, root, where, report))


def _complete_range(raw: dict[str, Any], location: Location) -> bool:
    region = raw["physicalLocation"].get("region", {})
    path = Path(location.path)
    return (
        region.get("endLine") is not None
        and location.start_line > 0
        and location.end_line >= location.start_line
        and bool(location.path)
        and not path.is_absolute()
        and ".." not in path.parts
    )


def _sarif_run(data: Any, report: Path) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise _no_completed(report, "expected a JSON object")
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise _no_completed(report, "expected exactly one run")
    run = runs[0]
    if not isinstance(run, dict):
        raise _no_completed(report, "runs[0] is not an object")
    return run


def _sarif_results(run: dict[str, Any], report: Path) -> list[Any]:
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
    return results


def _sarif_fingerprint(result: dict[str, Any], where: str, report: Path) -> str:
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
    return fingerprint


def _sarif_location_list(result: dict[str, Any], where: str, report: Path) -> list[Any]:
    locations = result.get("locations")
    related = result.get("relatedLocations", [])
    if not isinstance(locations, list) or not isinstance(related, list):
        raise _no_completed(report, f"{where} has malformed locations")
    return [*locations, *related]


def _sarif_raw_location(location: Any, root: Path, where: str, report: Path) -> Location:
    if not isinstance(location, dict):
        raise _no_completed(report, f"{where} has a non-object location")
    return _sarif_range(location, root, where, report)


def _sarif_locations(
    locations: list[Any], root: Path, where: str, report: Path
) -> tuple[tuple[Location, ...], bool]:
    formatted: list[Location] = []
    seen: set[Location] = set()
    complete = True
    for location in locations:
        span = _sarif_raw_location(location, root, where, report)
        complete &= _complete_range(location, span)
        if span not in seen:
            seen.add(span)
            formatted.append(span)
    if not formatted:
        raise _no_completed(report, f"{where} has no locations")
    return tuple(formatted), complete and len(formatted) >= 2


def _sarif_clone(result: Any, index: int, root: Path, report: Path) -> Clone:
    where = f"runs[0].results[{index}]"
    if not isinstance(result, dict):
        raise _no_completed(report, f"{where} is not an object")
    fingerprint = _sarif_fingerprint(result, where, report)
    raw_locations = _sarif_location_list(result, where, report)
    locations, complete = _sarif_locations(raw_locations, root, where, report)
    return Clone(fingerprint, locations, complete)


def _parse_sarif(report: Path, root: Path) -> list[Clone]:
    run = _sarif_run(_read_report(report), report)
    results = _sarif_results(run, report)
    return [_sarif_clone(result, index, root, report) for index, result in enumerate(results)]


def _format_source(name: object, raw: object) -> int | None:
    if not isinstance(name, str) or not isinstance(raw, dict):
        return None
    sources = raw.get("sources")
    if isinstance(sources, bool) or not isinstance(sources, int):
        return None
    return sources


def _format_sources(data: dict[str, Any]) -> dict[str, int] | None:
    statistics = data.get("statistics")
    if not isinstance(statistics, dict):
        return None
    formats = statistics.get("formats")
    if not isinstance(formats, dict):
        return None
    analyzed: dict[str, int] = {}
    for name, raw in formats.items():
        sources = _format_source(name, raw)
        if sources is None:
            return None
        analyzed[name] = sources
    return analyzed


def _files_with_suffix(files: list[str], suffix: str) -> list[str]:
    return [
        name for name in files if Path(name).suffix.lower() == suffix
    ]


def _missing_formats(
    files: list[str], analyzed: dict[str, int]
) -> set[str]:
    selected = Counter(Path(name).suffix.lower() for name in files)
    candidates: set[str] = set()
    for suffix, count in selected.items():
        format_name = FORMAT_BY_SUFFIX.get(suffix)
        if format_name is None or analyzed.get(format_name, 0) < count:
            candidates.update(_files_with_suffix(files, suffix))
    return candidates


def _selected_skipped(files: list[str], data: dict[str, Any]) -> list[str]:
    analyzed = _format_sources(data)
    if analyzed is None:
        return list(files)
    candidates = _missing_formats(files, analyzed)
    if not candidates:
        candidates.update(files)
    return sorted(candidates)


def _parse_jscpd_json(report: Path, files: list[str]) -> None:
    data = _required_object(
        _read_report(report), report, "expected a JSON object"
    )
    statistics = _required_object(
        data.get("statistics"), report, "statistics is not an object"
    )
    total = _required_object(
        statistics.get("total"),
        report,
        "statistics.total is not an object",
    )
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
        analysis_step("clone setup", _write_clone_config, config)
        command = analysis_step(
            "clone command preparation", _jscpd_command,
            binary, files, min_tokens, max_bytes, output, config,
        )
        mark_step("jscpd")
        result = run(command, cwd=root, budget_seconds=remaining_budget(600))
        diagnostics = result.diagnostics()
        record_diagnostics(diagnostics)
        _raise_jscpd_failure(result, diagnostics)
        sarif = output / "jscpd-report.sarif"
        json_report = output / "jscpd-report.json"
        if not sarif.is_file() or not json_report.is_file():
            raise CloneEvidenceError(
                f"jscpd wrote no report at {sarif} or {json_report}",
                diagnostics=diagnostics,
            )
        try:
            clones = analysis_step(
                "clone report analysis", _parse_reports, json_report, sarif, root, files
            )
        except UnsupportedError as error:
            raise CloneEvidenceError(
                str(error),
                diagnostics=diagnostics,
            ) from error
        return clones, diagnostics, result.execution


def _complete_clone_locations(clones: list[Clone], selected: set[str]) -> bool:
    return all(clone.complete for clone in clones) and all(
        location.path in selected for clone in clones for location in clone.locations
    )


def _clone_finding(fingerprint: str, actual: list[Clone], selected: set[str]) -> Finding:
    spans = _clone_spans(actual)
    locations = "; ".join(map(str, spans))
    return Finding(
        fingerprint, len(actual), locations,
        locations=spans if _complete_clone_locations(actual, selected) else None,
    )


def _clone_spans(clones: list[Clone]) -> tuple[Location, ...]:
    return tuple(location for clone in clones for location in clone.locations)


def _write_clone_config(config: Path) -> None:
    config.write_text("{}", encoding="utf-8")


def _parse_reports(json_report: Path, sarif: Path, root: Path, files: list[str]) -> list[Clone]:
    _parse_jscpd_json(json_report, files)
    return _parse_sarif(sarif, root)


def _clone_findings(clones: list[Clone], files: list[str]) -> list[Finding]:
    occurrences: dict[str, list[Clone]] = {}
    for clone in clones:
        occurrences.setdefault(clone.fingerprint, []).append(clone)
    selected = set(files)
    return [
        _clone_finding(fingerprint, occurrences[fingerprint], selected)
        for fingerprint in sorted(occurrences)
    ]


def measure_clones(
    root: Path,
    files: list[str],
    min_tokens: int,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> CloneMeasurement:
    try:
        binary = analysis_step("clone tool preparation", _jscpd_binary)
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
        analysis_step("clone findings", _clone_findings, clones, files), diagnostics, execution
    )
