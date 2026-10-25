"""jscpd invocation, SARIF parsing, the clone baseline and the clones command."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .files import validate_inventory
from .policy import Config, GateError, UsageError, _describe
from .tools import _jscpd_binary


@dataclass(frozen=True)
class Clone:
    fingerprint: str
    locations: tuple[str, ...]


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    count: int
    files: tuple[str, ...]
    reason: str


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
    location: dict[str, Any], root: Path, where: str
) -> str:
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
            raise GateError(f"invalid SARIF report {report}: runs[{run_index}] is not an object")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise GateError(f"invalid SARIF report {report}: runs[{run_index}].results is not a list")
        for result_index, result in enumerate(results):
            where = f"runs[{run_index}].results[{result_index}]"
            if not isinstance(result, dict):
                raise GateError(f"invalid SARIF report {report}: {where} is not an object")
            fingerprints = result.get("partialFingerprints")
            fingerprint = (
                fingerprints.get("jscpdCloneHash/v1")
                if isinstance(fingerprints, dict)
                else None
            )
            if not isinstance(fingerprint, str) or not fingerprint:
                raise GateError(
                    f"invalid SARIF report {report}: {where} has no "
                    "partialFingerprints[\"jscpdCloneHash/v1\"]"
                )
            locations = result.get("locations", [])
            related = result.get("relatedLocations", [])
            if not isinstance(locations, list) or not isinstance(related, list):
                raise GateError(f"invalid SARIF report {report}: {where} has malformed locations")
            formatted: list[str] = []
            seen: set[str] = set()
            for location in [*locations, *related]:
                if not isinstance(location, dict):
                    raise GateError(f"invalid SARIF report {report}: {where} has a non-object location")
                text = _sarif_location(location, root, where)
                if text not in seen:
                    seen.add(text)
                    formatted.append(text)
            if not formatted:
                raise GateError(f"invalid SARIF report {report}: {where} has no locations")
            clones.append(Clone(fingerprint, tuple(formatted)))
    return clones


def _run_jscpd(root: Path, binary: Path, files: list[str], min_tokens: int) -> list[Clone]:
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
            )
        except OSError as error:
            raise GateError(f"cannot run jscpd at {binary}: {error}") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise GateError(f"jscpd failed (exit {result.returncode}): {detail or 'no output'}")
        report = output / "jscpd-report.sarif"
        if not report.is_file():
            raise GateError(f"jscpd wrote no report at {report}")
        return _parse_sarif(report, root)


def _baseline_error(path: Path, key: str, expected: str, actual: str) -> GateError:
    return GateError(f"{path}: {key}: expected {expected}, got {actual}")


def load_baseline(path: Path) -> list[BaselineEntry]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise GateError(f"cannot read baseline {path}: {error}") from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise GateError(f"invalid baseline {path}: {error}") from error

    raw_entries = data.get("clone", [])
    if not isinstance(raw_entries, list):
        raise _baseline_error(path, "clone", "an array of tables", _describe(raw_entries))
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        where = f"clone[{index}]"
        if not isinstance(raw, dict):
            raise _baseline_error(path, where, "a table", _describe(raw))
        fingerprint = raw.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise _baseline_error(
                path,
                f"{where}.fingerprint",
                "a non-empty string",
                "missing" if fingerprint is None else _describe(fingerprint),
            )
        if fingerprint in seen:
            raise _baseline_error(
                path,
                f"{where}.fingerprint",
                "a unique fingerprint",
                f"duplicate {fingerprint!r}",
            )
        seen.add(fingerprint)
        count = raw.get("count", 1)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise _baseline_error(
                path, f"{where}.count", "an integer >= 0", _describe(count)
            )
        files = raw.get("files", [])
        if not isinstance(files, list) or any(
            not isinstance(item, str) for item in files
        ):
            raise _baseline_error(
                path, f"{where}.files", "a list of strings", _describe(files)
            )
        reason = raw.get("reason", "")
        if not isinstance(reason, str):
            raise _baseline_error(
                path, f"{where}.reason", "a string", _describe(reason)
            )
        entries.append(
            BaselineEntry(fingerprint, count, tuple(files), reason)
        )
    return entries


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _write_baseline(path: Path, entries: list[BaselineEntry]) -> None:
    if not entries:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise GateError(f"cannot remove empty baseline {path}: {error}") from error
        return
    lines = [
        "# Clone baseline: each entry accepts a clone fingerprint, count times,",
        "# for the stated reason. Add new entries by hand; --prune only removes",
        "# resolved entries and lowers counts.",
        "",
    ]
    for entry in entries:
        lines.append("[[clone]]")
        lines.append(f"fingerprint = {_toml_string(entry.fingerprint)}")
        lines.append(f"count = {entry.count}")
        files = ", ".join(_toml_string(item) for item in entry.files)
        lines.append(f"files = [{files}]")
        lines.append(f"reason = {_toml_string(entry.reason)}")
        lines.append("")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=str(path.parent)
        )
    except OSError as error:
        raise GateError(f"cannot write baseline {path}: {error}") from error
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines))
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise GateError(f"cannot write baseline {path}: {error}") from error


def _format_files(files: tuple[str, ...]) -> str:
    return ", ".join(files) if files else "(no files recorded)"


def command_clones(root: Path, config: Config, prune: bool = False) -> int:
    clone_config = config.clones
    if clone_config is None:
        print(f"clones: [clones] is not configured in {config.path}", file=sys.stderr)
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
    selected = sorted(
        relative
        for relative in files
        if classes.get(relative) in clone_config.classes
    )
    if not selected:
        classes_text = ", ".join(clone_config.classes) or "none"
        print(f"clones: no files in classes ({classes_text}); nothing to analyze", file=sys.stderr)
        return 1

    try:
        binary = _jscpd_binary()
    except UsageError as error:
        print(f"clones: {error}", file=sys.stderr)
        return 2
    except GateError as error:
        print(f"clones: {error}", file=sys.stderr)
        return 1
    try:
        clones = _run_jscpd(root, binary, selected, clone_config.min_tokens)
        entries = load_baseline(clone_config.baseline)
    except GateError as error:
        print(f"clones: {error}", file=sys.stderr)
        return 1

    occurrences: dict[str, list[Clone]] = {}
    for clone in clones:
        occurrences.setdefault(clone.fingerprint, []).append(clone)

    known = {entry.fingerprint for entry in entries}
    failures: list[str] = []
    resolved: list[BaselineEntry] = []
    kept: list[BaselineEntry] = []
    empty_reason = False

    for entry in entries:
        actual = occurrences.get(entry.fingerprint, [])
        if not entry.reason.strip():
            empty_reason = True
            locations = "; ".join(
                ", ".join(clone.locations) for clone in actual
            )
            detail = f"files: {_format_files(entry.files)}"
            if locations:
                detail += f"; reported at: {locations}"
            failures.append(f"baseline entry {entry.fingerprint}: empty reason ({detail})")
        if not actual:
            resolved.append(entry)
            continue
        if len(actual) > entry.count:
            locations = "; ".join(
                ", ".join(clone.locations) for clone in actual
            )
            times = "time" if len(actual) == 1 else "times"
            failures.append(
                f"clone {entry.fingerprint} occurs {len(actual)} {times} but "
                f"the baseline count is {entry.count}: {locations}"
            )
        kept.append(
            BaselineEntry(
                entry.fingerprint,
                min(entry.count, len(actual)),
                entry.files,
                entry.reason,
            )
        )

    for fingerprint, actual in occurrences.items():
        if fingerprint in known:
            continue
        for clone in actual:
            failures.append(f"new clone {fingerprint}: {', '.join(clone.locations)}")

    for entry in resolved:
        print(f"clones: resolved {entry.fingerprint} (files: {_format_files(entry.files)})")

    if prune and not empty_reason:
        baseline_existed = clone_config.baseline.exists()
        try:
            _write_baseline(clone_config.baseline, kept)
        except GateError as error:
            print(f"clones: {error}", file=sys.stderr)
            return 1
        if kept:
            print(f"clones: baseline updated at {clone_config.baseline}")
        elif baseline_existed:
            print(f"clones: baseline removed at {clone_config.baseline}")

    if failures:
        for failure in failures:
            print(f"clones: {failure}", file=sys.stderr)
        return 1
    if clones:
        noun = "clone" if len(clones) == 1 else "clones"
        print(f"clones: {len(clones)} {noun} within baseline")
    else:
        print("clones: 0 clones")
    return 0
