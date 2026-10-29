"""Declared single-owner rules: policy validation and complete inventory scan."""

from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import stat
import sys
import tempfile
import time
import tokenize
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .files import _shebang_interpreter
from .owners_match import Occurrence, covered
from .owners_python import python_code, python_events
from .owners_shell import shell_events
from .policy import ConfigError, GateError, _check_keys, _config_error, _string, _string_list
from .ratchet import Finding, Location
from .runner import run


KINDS = (
    "python-call",
    "python-import",
    "python-argv",
    "python-script",
    "shell-command",
    "shell-script",
    "text-regex",
)
REGEX_RUNNER = Path(__file__).with_name("owners_regex.py")


@dataclass(frozen=True)
class Pattern:
    kind: str
    value: str
    paths: tuple[str, ...] = ()

    def applies(self, relative: str) -> bool:
        return not self.paths or any(fnmatch.fnmatchcase(relative, item) for item in self.paths)

    def label(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True)
class OwnerRule:
    name: str
    reason: str
    owners: tuple[str, ...]
    forbid: tuple[Pattern, ...]
    allow: tuple[Pattern, ...]


@dataclass(frozen=True)
class OwnersSpec:
    rules: tuple[OwnerRule, ...]


def _nonempty_list(raw: dict[str, Any], key: str, path: Path, where: str) -> tuple[str, ...]:
    values = _string_list(raw, key, path, where)
    if not values or any(not item.strip() or "\x00" in item for item in values):
        raise _config_error(
            path, where, "a non-empty list of non-empty strings without NUL", repr(values)
        )
    return values


def _safe_owner(value: str) -> bool:
    return not value.startswith("/") and all(
        part not in ("", ".", "..") for part in value.split("/")
    )


def _owner_paths(raw: dict[str, Any], path: Path, where: str) -> tuple[str, ...]:
    values = _nonempty_list(raw, "owners", path, f"{where}.owners")
    for value in values:
        if not _safe_owner(value):
            raise _config_error(
                path, f"{where}.owners", "repository-relative file paths", repr(value)
            )
    if len(set(values)) != len(values):
        raise _config_error(path, f"{where}.owners", "distinct owner files", repr(values))
    return values


def _validate_pattern(kind: str, value: str, path: Path, where: str) -> None:
    if kind not in KINDS:
        raise _config_error(path, f"{where}.kind", f"one of {', '.join(KINDS)}", repr(kind))
    if "\x00" in value:
        raise _config_error(path, f"{where}.value", "a value without NUL", "embedded NUL")
    if kind == "text-regex":
        try:
            re.compile(value)
        except re.error as error:
            raise _config_error(
                path, f"{where}.value", "a valid regular expression", str(error)
            ) from error


def _pattern(raw: Any, path: Path, where: str) -> Pattern:
    if not isinstance(raw, dict):
        raise _config_error(path, where, "a pattern table", repr(raw))
    _check_keys(raw, ("kind", "value", "paths"), path, where)
    kind = _string(raw, "kind", path, f"{where}.kind")
    value = _string(raw, "value", path, f"{where}.value")
    _validate_pattern(kind, value, path, where)
    paths = _nonempty_list(raw, "paths", path, f"{where}.paths") if "paths" in raw else ()
    return Pattern(kind, value, paths)


def _pattern_entries(raw: dict[str, Any], key: str, path: Path, where: str) -> list[Any]:
    entries = raw.get(key, [])
    if not _valid_pattern_entries(entries, key):
        raise _config_error(
            path,
            f"{where}.{key}",
            _pattern_array_description(key),
            repr(entries),
        )
    return entries


def _valid_pattern_entries(entries: Any, key: str) -> bool:
    return isinstance(entries, list) and (key != "forbid" or bool(entries))


def _pattern_array_description(key: str) -> str:
    return "a non-empty array of patterns" if key == "forbid" else "an array of patterns"


def _unique_patterns(patterns: tuple[Pattern, ...], path: Path, where: str) -> None:
    identities = [(item.kind, item.value) for item in patterns]
    if len(set(identities)) != len(identities):
        raise _config_error(path, where, "distinct pattern kinds and values", repr(identities))


def _patterns(raw: dict[str, Any], key: str, path: Path, where: str) -> tuple[Pattern, ...]:
    entries = _pattern_entries(raw, key, path, where)
    patterns = tuple(
        _pattern(item, path, f"{where}.{key}[{index}]") for index, item in enumerate(entries)
    )
    _unique_patterns(patterns, path, f"{where}.{key}")
    return patterns


def _rule(raw: Any, path: Path, where: str) -> OwnerRule:
    if not isinstance(raw, dict):
        raise _config_error(path, where, "a rule table", repr(raw))
    _check_keys(raw, ("name", "reason", "owners", "forbid", "allow"), path, where)
    return OwnerRule(
        _string(raw, "name", path, f"{where}.name"),
        _string(raw, "reason", path, f"{where}.reason"),
        _owner_paths(raw, path, where),
        _patterns(raw, "forbid", path, where),
        _patterns(raw, "allow", path, where),
    )


def _unique_rules(rules: tuple[OwnerRule, ...], path: Path, where: str) -> None:
    names = [rule.name for rule in rules]
    if len(set(names)) != len(names):
        raise _config_error(path, f"{where}.rule", "distinct rule names", repr(names))


def _rules(raw: dict[str, Any], path: Path, where: str) -> tuple[OwnerRule, ...]:
    entries = raw.get("rule")
    if not isinstance(entries, list) or not entries:
        raise _config_error(path, f"{where}.rule", "a non-empty array of rules", repr(entries))
    rules = tuple(_rule(item, path, f"{where}.rule[{index}]") for index, item in enumerate(entries))
    _unique_rules(rules, path, where)
    return rules


def parse_owners(raw: dict[str, Any], path: Path, where: str) -> OwnersSpec:
    return OwnersSpec(_rules(raw, path, where))


def _parent_fd(root: Path, relative: str) -> int:
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(relative).parts[:-1]:
            following = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = following
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _read_regular(root: Path, relative: str) -> bytes | None:
    parent = -1
    try:
        parent = _parent_fd(root, relative)
        name = PurePosixPath(relative).name
        if not stat.S_ISREG(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
            return None
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GateError(f"cannot scan {relative}: expected a regular file")
            return stream.read()
    except OSError as error:
        raise GateError(f"cannot scan {relative}: {error}") from error
    finally:
        if parent >= 0:
            os.close(parent)


def _is_shell(suffix: str, interpreter: str) -> bool:
    return suffix in (".sh", ".bash", ".zsh", ".ksh") or interpreter in (
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
    )


def _language(relative: str, data: bytes) -> str:
    suffix = PurePosixPath(relative).suffix.lower()
    first = data[:4096].decode("utf-8", "replace").split("\n", 1)[0]
    interpreter = _shebang_interpreter(first) or ""
    if suffix == ".py" or interpreter.startswith("python"):
        return "python"
    if _is_shell(suffix, interpreter):
        return "shell"
    return "text"


def _source(relative: str, data: bytes, language: str) -> str:
    if language != "python":
        return data.decode("utf-8", "replace")
    try:
        encoding, _lines = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    except (SyntaxError, UnicodeDecodeError, LookupError) as error:
        raise GateError(f"cannot decode Python {relative}: {error}") from error


def _quoted_end(source: str, index: int) -> int:
    quote = source[index]
    index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return index


def _line_comment(source: str, index: int, relative: str) -> bool:
    return (
        source[index] == "#"
        or source.startswith("//", index)
        or (relative.endswith(".el") and source[index] == ";")
    )


def _block_end(source: str, index: int) -> int:
    end = source.find("*/", index + 2)
    return len(source) if end < 0 else end + 2


def _line_end(source: str, index: int) -> int:
    end = source.find("\n", index)
    return len(source) if end < 0 else end


def _mask_end(source: str, index: int, relative: str) -> int | None:
    if source[index] in "'\"`":
        return _quoted_end(source, index)
    if source.startswith("/*", index):
        return _block_end(source, index)
    if _line_comment(source, index, relative):
        return _line_end(source, index)
    return None


def _blank(chars: list[str], start: int, end: int) -> None:
    for position in range(start, min(end, len(chars))):
        if chars[position] not in "\r\n":
            chars[position] = " "


def _generic_code(source: str, relative: str) -> str:
    """Mask common quoted strings and line/block comments in other text files."""
    chars = list(source)
    index = 0
    while index < len(source):
        end = _mask_end(source, index, relative)
        if end is None:
            index += 1
        else:
            _blank(chars, index, end)
            index = end
    return "".join(chars)


def _run_regex(jobs: list[dict[str, Any]], deadline: float) -> str:
    with tempfile.TemporaryDirectory(prefix="qg-owners-") as directory:
        job = Path(directory) / "job.json"
        job.write_text(json.dumps(jobs), encoding="utf-8")
        result = run(
            [sys.executable, "-I", str(REGEX_RUNNER), str(job)],
            budget_seconds=max(0.0, deadline - time.monotonic()),
            capture_limit=None,
        )
    if result.execution != "completed" or result.returncode != 0:
        raise GateError(
            f"owners text regular expressions failed: {result.execution}: {result.stderr_text.strip()}"
        )
    return result.stdout_text


def _regex_events(jobs: list[dict[str, Any]], deadline: float) -> dict[str, list[Occurrence]]:
    if not jobs:
        return {}
    try:
        matches = json.loads(_run_regex(jobs, deadline))
        return {
            path: [
                Occurrence("text-regex", value, line, start, end, ("text", start), frozenset())
                for value, line, start, end in items
            ]
            for path, items in matches.items()
        }
    except (ValueError, TypeError, KeyError) as error:
        raise GateError(f"invalid owners text regular expression results: {error}") from error


def _patterns_for_file(spec: OwnersSpec, relative: str) -> list[Pattern]:
    return [
        pattern
        for rule in spec.rules
        for pattern in (*rule.forbid, *rule.allow)
        if pattern.applies(relative)
    ]


def _python_file(relative: str, source: str, kinds: set[str]) -> tuple[list[Occurrence], str]:
    events = []
    if kinds & {"python-call", "python-import", "python-argv", "python-script"}:
        events = python_events(relative, source)
    if not kinds & {"python-argv", "python-script"}:
        events = [event for event in events if event.kind != "unanalysable"]
    code = python_code(relative, source) if "text-regex" in kinds else source
    return events, code


def _source_events(
    relative: str, source: str, language: str, kinds: set[str]
) -> tuple[list[Occurrence], str]:
    if language == "python":
        return _python_file(relative, source, kinds)
    if language == "shell":
        return _shell_file(relative, source, kinds)
    if language == "text":
        return _text_file(relative, source, kinds)
    return [], source


def _shell_file(relative: str, source: str, kinds: set[str]) -> tuple[list[Occurrence], str]:
    if kinds & {"shell-command", "shell-script", "text-regex"}:
        events, code = shell_events(relative, source)
        if not kinds & {"shell-command", "shell-script"}:
            events = [event for event in events if event.kind != "unanalysable"]
        return events, code
    return [], source


def _text_file(relative: str, source: str, kinds: set[str]) -> tuple[list[Occurrence], str]:
    return [], _generic_code(source, relative) if "text-regex" in kinds else source


def _regex_job(relative: str, code: str, patterns: list[Pattern]) -> dict[str, Any] | None:
    expressions = sorted({pattern.value for pattern in patterns if pattern.kind == "text-regex"})
    return {"path": relative, "source": code, "patterns": expressions} if expressions else None


def _scan_file(
    relative: str, data: bytes, patterns: list[Pattern]
) -> tuple[list[Occurrence], dict[str, Any] | None]:
    if not patterns:
        return [], None
    language = _language(relative, data)
    source = _source(relative, data, language)
    kinds = {pattern.kind for pattern in patterns}
    events, code = _source_events(relative, source, language, kinds)
    return events, _regex_job(relative, code, patterns)


def _file_events(
    root: Path, files: list[str], spec: OwnersSpec, deadline: float
) -> tuple[dict[str, list[Occurrence]], set[str]]:
    events: dict[str, list[Occurrence]] = {}
    regular: set[str] = set()
    jobs = []
    for relative in files:
        data = _read_regular(root, relative)
        if data is None:
            continue
        regular.add(relative)
        events[relative], job = _scan_file(relative, data, _patterns_for_file(spec, relative))
        if job is not None:
            jobs.append(job)
    for relative, matches in _regex_events(jobs, deadline).items():
        events[relative].extend(matches)
    return events, regular


def _hits(pattern: Pattern, relative: str, events: list[Occurrence]) -> list[Occurrence]:
    if not pattern.applies(relative):
        return []
    return [item for item in events if item.kind == pattern.kind and item.value == pattern.value]


def _subject(rule: OwnerRule, relative: str, pattern: Pattern) -> str:
    return json.dumps(
        [rule.name, relative, pattern.kind, pattern.value], ensure_ascii=True, separators=(",", ":")
    )


def _finding(rule: OwnerRule, relative: str, pattern: Pattern, hits: list[Occurrence]) -> Finding:
    lines = sorted(item.line for item in hits)
    return Finding(
        _subject(rule, relative, pattern),
        len(hits),
        f"{relative}:{lines[0]}",
        {
            "rule": rule.name,
            "pattern": pattern.label(),
            "owners": list(rule.owners),
            "lines": lines,
            "text_fallback": pattern.kind == "text-regex",
        },
        tuple(Location(relative, line, line) for line in lines),
    )


def _check_patterns(rule: OwnerRule, counts: dict[Pattern, int]) -> None:
    for category, patterns in (("forbid", rule.forbid), ("allow", rule.allow)):
        for pattern in patterns:
            if not counts[pattern]:
                raise ConfigError(
                    f"owners: rule {rule.name}: {category} pattern {pattern.label()!r} matches nothing"
                )


def _check_stale(
    rule: OwnerRule, regular: set[str], counts: dict[Pattern, int], *, complete: bool
) -> None:
    for owner in rule.owners:
        if owner not in regular:
            raise ConfigError(
                f"owners: rule {rule.name}: owner file {owner} is missing or not an enumerated regular file"
            )
    if complete:
        _check_patterns(rule, counts)


def _uncovered(hits: list[Occurrence], allowed: list[Occurrence]) -> list[Occurrence]:
    return [hit for hit in hits if not any(covered(hit, exemption) for exemption in allowed)]


def _allowed_hits(rule: OwnerRule, matches: dict[Pattern, list[Occurrence]]) -> list[Occurrence]:
    return [hit for pattern in rule.allow for hit in matches[pattern]]


def _file_findings(
    rule: OwnerRule, relative: str, matches: dict[Pattern, list[Occurrence]]
) -> list[Finding]:
    if relative in rule.owners:
        return []
    allowed = _allowed_hits(rule, matches)
    findings = []
    for pattern in rule.forbid:
        hits = _uncovered(matches[pattern], allowed)
        if hits:
            findings.append(_finding(rule, relative, pattern, hits))
    return findings


def _rule_findings(
    rule: OwnerRule, events: dict[str, list[Occurrence]], regular: set[str]
) -> list[Finding]:
    counts = {pattern: 0 for pattern in (*rule.forbid, *rule.allow)}
    findings = []
    for relative, items in events.items():
        matches = {pattern: _hits(pattern, relative, items) for pattern in counts}
        for pattern, hits in matches.items():
            counts[pattern] += len(hits)
        findings.extend(_file_findings(rule, relative, matches))
    _check_stale(rule, regular, counts, complete=_analysis_complete(events))
    return findings


def _analysis_complete(events: dict[str, list[Occurrence]]) -> bool:
    return not any(item.kind == "unanalysable" for items in events.values() for item in items)


def _analysis_finding(path: str, word: str, reason: str, items: list[Occurrence]) -> Finding:
    lines = sorted(item.line for item in items)
    subject = json.dumps(["unanalysable", path, word, reason], ensure_ascii=True, separators=(",", ":"))
    return Finding(subject, len(lines), f"{path}:{lines[0]}",
                   {"kind": "unanalysable", "word": word, "reason": reason, "lines": lines},
                   tuple(Location(path, line, line) for line in lines), kind="unanalysable")


def _analysis_findings(events: dict[str, list[Occurrence]]) -> list[Finding]:
    groups: dict[tuple[str, str, str], list[Occurrence]] = {}
    for path, items in events.items():
        for item in items:
            if item.kind == "unanalysable":
                groups.setdefault((path, item.value, item.reason or "unknown"), []).append(item)
    return [_analysis_finding(*key, items) for key, items in groups.items()]


def measure_owners(
    root: Path, files: list[str], spec: OwnersSpec, *, budget_seconds: int = 600
) -> list[Finding]:
    events, regular = _file_events(root, files, spec, time.monotonic() + budget_seconds)
    findings = [finding for rule in spec.rules for finding in _rule_findings(rule, events, regular)]
    findings.extend(_analysis_findings(events))
    return sorted(findings, key=lambda finding: finding.subject)
