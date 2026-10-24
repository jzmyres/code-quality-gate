#!/usr/bin/env python3
"""quality-gate: inventory, hygiene, clone ratchet and pinned tools.

Run as 'python3 -I qg.py [--repo DIR] COMMAND'.  DIR is the top level of
a git work tree and its configuration is 'quality-gate.toml'.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MIN_TOKENS = 50
TOOLS_FETCH = "python3 -I qg.py tools fetch"


class GateError(Exception):
    """A check could not pass."""

    exit_code = 1


class UsageError(GateError):
    """The command or its configuration is malformed."""

    exit_code = 2


class ConfigError(UsageError):
    """quality-gate.toml is missing or invalid."""


@dataclass(frozen=True)
class Rule:
    index: int
    pattern: str
    class_name: str
    reason: str


@dataclass(frozen=True)
class ClassDef:
    name: str
    code: bool
    description: str


@dataclass(frozen=True)
class CloneConfig:
    classes: tuple[str, ...]
    min_tokens: int
    baseline: Path


@dataclass(frozen=True)
class Config:
    path: Path
    root: Path
    code_patterns: tuple[str, ...]
    code_shebangs: tuple[str, ...]
    classes: dict[str, ClassDef]
    rules: tuple[Rule, ...]
    max_bytes: int
    clones: CloneConfig | None


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str
    sha256: str
    binary: str


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


def _config_error(path: Path, key: str, expected: str, actual: str) -> ConfigError:
    return ConfigError(f"{path}: {key}: expected {expected}, got {actual}")


def _describe(value: object) -> str:
    if isinstance(value, (str, int, float, bool)):
        return f"{type(value).__name__} {value!r}"
    return type(value).__name__


def _required_table(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> dict[str, Any]:
    if key not in parent:
        raise _config_error(path, full_key, "a table", "missing")
    value = parent[key]
    if not isinstance(value, dict):
        raise _config_error(path, full_key, "a table", _describe(value))
    return value


def _optional_table(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> dict[str, Any] | None:
    if key not in parent:
        return None
    value = parent[key]
    if not isinstance(value, dict):
        raise _config_error(path, full_key, "a table", _describe(value))
    return value


def _string(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    allow_empty: bool = False,
) -> str:
    if key not in parent:
        raise _config_error(path, full_key, "a non-empty string", "missing")
    value = parent[key]
    if not isinstance(value, str):
        raise _config_error(path, full_key, "a string", _describe(value))
    if not allow_empty and not value.strip():
        raise _config_error(path, full_key, "a non-empty string", _describe(value))
    return value


def _string_list(
    parent: dict[str, Any], key: str, path: Path, full_key: str
) -> tuple[str, ...]:
    if key not in parent:
        raise _config_error(path, full_key, "a list of strings", "missing")
    value = parent[key]
    if not isinstance(value, list):
        raise _config_error(path, full_key, "a list of strings", _describe(value))
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise _config_error(
                path, f"{full_key}[{index}]", "a string", _describe(item)
            )
    return tuple(value)


def _boolean(parent: dict[str, Any], key: str, path: Path, full_key: str) -> bool:
    if key not in parent:
        raise _config_error(path, full_key, "a boolean", "missing")
    value = parent[key]
    if not isinstance(value, bool):
        raise _config_error(path, full_key, "a boolean", _describe(value))
    return value


def _integer(
    parent: dict[str, Any],
    key: str,
    path: Path,
    full_key: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
) -> int:
    if key not in parent:
        if default is None:
            raise _config_error(path, full_key, "an integer", "missing")
        return default
    value = parent[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _config_error(path, full_key, "an integer", _describe(value))
    if minimum is not None and value < minimum:
        raise _config_error(path, full_key, f"an integer >= {minimum}", str(value))
    return value


def load_config(root: Path) -> Config:
    path = root / "quality-gate.toml"
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError:
        raise ConfigError(
            f"{path}: expected a configuration file, got missing"
        ) from None
    except OSError as error:
        raise ConfigError(
            f"{path}: expected a readable configuration file, got {error}"
        ) from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ConfigError(f"{path}: expected valid TOML, got {error}") from error

    code = _required_table(data, "code", path, "code")
    patterns = _string_list(code, "patterns", path, "code.patterns")
    shebangs = _string_list(code, "shebangs", path, "code.shebangs")

    classes_raw = _required_table(data, "classes", path, "classes")
    classes: dict[str, ClassDef] = {}
    for name, raw in classes_raw.items():
        if not isinstance(raw, dict):
            raise _config_error(
                path, f"classes.{name}", "a table", _describe(raw)
            )
        classes[name] = ClassDef(
            name=name,
            code=_boolean(raw, "code", path, f"classes.{name}.code"),
            description=_string(
                raw, "description", path, f"classes.{name}.description"
            ),
        )

    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise _config_error(path, "rule", "an array of tables", _describe(raw_rules))
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        full_key = f"rule[{index}]"
        if not isinstance(raw, dict):
            raise _config_error(path, full_key, "a table", _describe(raw))
        rules.append(
            Rule(
                index=index,
                pattern=_string(
                    raw, "pattern", path, f"{full_key}.pattern", allow_empty=True
                ),
                class_name=_string(raw, "class", path, f"{full_key}.class"),
                reason=_string(
                    raw, "reason", path, f"{full_key}.reason", allow_empty=True
                ),
            )
        )

    hygiene = _optional_table(data, "hygiene", path, "hygiene")
    max_bytes = DEFAULT_MAX_BYTES
    if hygiene is not None:
        max_bytes = _integer(
            hygiene,
            "max_bytes",
            path,
            "hygiene.max_bytes",
            default=DEFAULT_MAX_BYTES,
            minimum=0,
        )

    clones_raw = _optional_table(data, "clones", path, "clones")
    clones: CloneConfig | None = None
    if clones_raw is not None:
        class_names = _string_list(clones_raw, "classes", path, "clones.classes")
        for class_name in class_names:
            if class_name not in classes:
                known = ", ".join(sorted(classes)) or "none"
                raise _config_error(
                    path,
                    "clones.classes",
                    f"a list of configured classes ({known})",
                    f"unknown class {class_name!r}",
                )
        min_tokens = _integer(
            clones_raw,
            "min_tokens",
            path,
            "clones.min_tokens",
            default=DEFAULT_MIN_TOKENS,
            minimum=1,
        )
        baseline_name = _string(clones_raw, "baseline", path, "clones.baseline")
        baseline = Path(baseline_name)
        if not baseline.is_absolute():
            baseline = root / baseline
        clones = CloneConfig(tuple(class_names), min_tokens, baseline)

    return Config(
        path=path,
        root=root,
        code_patterns=patterns,
        code_shebangs=shebangs,
        classes=classes,
        rules=tuple(rules),
        max_bytes=max_bytes,
        clones=clones,
    )


def resolve_repo(value: str | None) -> Path:
    raw = Path(value) if value is not None else Path.cwd()
    try:
        root = raw.resolve(strict=True)
    except OSError as error:
        raise UsageError(
            f"{raw}: expected the top level of a git work tree, got {error}"
        ) from error
    if not root.is_dir():
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got a non-directory"
        )
    command = [
        "git",
        "-c",
        f"safe.directory={root}",
        "-C",
        str(root),
        "rev-parse",
        "--show-toplevel",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as error:
        raise UsageError(f"{root}: cannot run git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or "git rev-parse failed"
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got {detail}"
        )
    top = Path(result.stdout.strip())
    try:
        top = top.resolve(strict=True)
    except OSError:
        pass
    if top != root:
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got {top}"
        )
    return root


def _git(root: Path, args: list[str], what: str) -> bytes:
    command = ["git", "-c", f"safe.directory={root}", "-C", str(root), *args]
    try:
        result = subprocess.run(command, capture_output=True)
    except OSError as error:
        raise GateError(f"{what} failed: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"{what} failed: {detail or f'git exited {result.returncode}'}")
    return result.stdout


def enumerate_files(root: Path) -> list[str]:
    raw = _git(
        root, ["ls-files", "-z", "-co", "--exclude-standard"], "file enumeration"
    )
    names = raw.decode("utf-8", "surrogateescape").split("\0")
    return sorted(name for name in names if name)


def _shebang_interpreter(first_line: str) -> str | None:
    if not first_line.startswith("#!"):
        return None
    words = first_line[2:].strip().split()
    if not words:
        return None
    name = PurePosixPath(words[0]).name
    if name != "env":
        return name
    index = 1
    while index < len(words):
        word = words[index]
        if word.startswith("-") or "=" in word:
            index += 1
            continue
        break
    if index >= len(words):
        return None
    return PurePosixPath(words[index]).name


def _is_code(path: Path, relative: str, config: Config) -> bool:
    if any(
        fnmatch.fnmatchcase(relative, pattern)
        for pattern in config.code_patterns
    ):
        return True
    if not config.code_shebangs:
        return False
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        interpreter = _shebang_interpreter(stream.readline())
    if interpreter is None:
        return False
    return any(
        fnmatch.fnmatchcase(interpreter, pattern)
        for pattern in config.code_shebangs
    )


def validate_inventory(
    root: Path, config: Config
) -> tuple[list[str], dict[str, str], list[str]]:
    files = enumerate_files(root)
    matched = [0] * len(config.rules)
    classes: dict[str, str] = {}
    violations: list[str] = []
    known_classes = ", ".join(sorted(config.classes)) or "none"

    for rule in config.rules:
        if not rule.pattern:
            violations.append(
                f"rule[{rule.index}]: empty pattern (expected a non-empty pattern)"
            )
        if not rule.reason.strip():
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): "
                "empty reason (expected a non-empty reason)"
            )
        if rule.class_name not in config.classes:
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): "
                f"unknown class {rule.class_name!r} (known classes: {known_classes})"
            )

    for relative in files:
        hits = [
            (index, rule)
            for index, rule in enumerate(config.rules)
            if fnmatch.fnmatchcase(relative, rule.pattern)
        ]
        for index, _rule in hits:
            matched[index] += 1
        if not hits:
            violations.append(f"{relative}: unclassified (no rule matches)")
            continue
        if len(hits) > 1:
            patterns = ", ".join(repr(rule.pattern) for _index, rule in hits)
            violations.append(
                f"{relative}: matches {len(hits)} rules ({patterns})"
            )
            continue
        rule = hits[0][1]
        class_def = config.classes.get(rule.class_name)
        if class_def is None:
            continue
        classes[relative] = rule.class_name
        try:
            code = _is_code(root / relative, relative, config)
        except OSError as error:
            violations.append(f"{relative}: cannot read shebang: {error}")
            continue
        if code and not class_def.code:
            violations.append(
                f"{relative}: code file classified as {rule.class_name!r} "
                f"(rule {rule.pattern!r})"
            )

    for index, rule in enumerate(config.rules):
        if matched[index] == 0:
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): matches no file"
            )
    return files, classes, violations


def command_inventory(
    root: Path, config: Config, list_class: str | None = None
) -> int:
    if list_class is not None and list_class not in config.classes:
        known = ", ".join(sorted(config.classes)) or "none"
        print(
            f"inventory: unknown class {list_class!r}; known classes: {known}",
            file=sys.stderr,
        )
        return 2
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        print(f"inventory: {error}", file=sys.stderr)
        return 1
    if violations:
        for violation in violations:
            print(f"inventory: {violation}", file=sys.stderr)
        return 1
    if list_class is not None:
        for relative in sorted(classes):
            if classes[relative] == list_class:
                print(relative)
        return 0
    print(f"inventory: {len(files)} files match {len(config.rules)} rules")
    return 0


def command_hygiene(root: Path, config: Config) -> int:
    try:
        raw = _git(
            root,
            ["ls-files", "-z", "-c", "-i", "--exclude-standard"],
            "ignored-file enumeration",
        )
        ignored = [
            name
            for name in raw.decode("utf-8", "surrogateescape").split("\0")
            if name
        ]
        if ignored:
            for relative in ignored:
                print(
                    f"hygiene: tracked file matches ignore rules: {relative}",
                    file=sys.stderr,
                )
            return 1
        files = enumerate_files(root)
    except GateError as error:
        print(f"hygiene: {error}", file=sys.stderr)
        return 1

    violations: list[str] = []
    for relative in files:
        try:
            size = (root / relative).stat().st_size
        except OSError as error:
            violations.append(f"{relative}: cannot measure size: {error}")
            continue
        if size > config.max_bytes:
            violations.append(
                f"{relative}: {size} bytes exceeds max_bytes {config.max_bytes}"
            )
    if violations:
        for violation in violations:
            print(f"hygiene: {violation}", file=sys.stderr)
        return 1
    print(f"hygiene: {len(files)} files within {config.max_bytes} bytes")
    return 0


def _default_lock_path() -> Path:
    return Path(__file__).resolve().parent / "tools.lock.toml"


def _tools_dir() -> Path:
    configured = os.environ.get("QG_TOOLS_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "share" / "quality-gate" / "tools"


def _tool_error(lock: Path, key: str, expected: str, actual: str) -> UsageError:
    return UsageError(f"{lock}: {key}: expected {expected}, got {actual}")


def _safe_relative_binary(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(path.parts) and not path.is_absolute() and ".." not in path.parts


def load_tools(lock: Path) -> dict[str, Tool]:
    try:
        with lock.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError:
        raise UsageError(f"{lock}: expected a tool lock file, got missing") from None
    except OSError as error:
        raise UsageError(
            f"{lock}: expected a readable tool lock file, got {error}"
        ) from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise UsageError(f"{lock}: expected valid TOML, got {error}") from error

    tools: dict[str, Tool] = {}
    for name, raw in data.items():
        full_key = name
        if not isinstance(raw, dict):
            raise _tool_error(lock, full_key, "a table", _describe(raw))
        version = _string(raw, "version", lock, f"{full_key}.version")
        url = _string(raw, "url", lock, f"{full_key}.url")
        digest = _string(raw, "sha256", lock, f"{full_key}.sha256")
        if len(digest) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in digest
        ):
            raise _tool_error(
                lock,
                f"{full_key}.sha256",
                "a 64-character hexadecimal SHA-256",
                _describe(digest),
            )
        binary = _string(raw, "binary", lock, f"{full_key}.binary")
        if not _safe_relative_binary(binary):
            raise _tool_error(
                lock,
                f"{full_key}.binary",
                "a safe relative path",
                _describe(binary),
            )
        tools[name] = Tool(
            name=name,
            version=version,
            url=url,
            sha256=digest.lower(),
            binary=binary,
        )
    return tools


def _tool_binary(tool: Tool, tools_root: Path) -> Path:
    return tools_root / f"{tool.name}-{tool.version}" / tool.binary


def _download(tool: Tool, target: Path) -> None:
    try:
        with urllib.request.urlopen(tool.url, timeout=60) as response:
            with target.open("wb") as stream:
                shutil.copyfileobj(response, stream)
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
        http.client.HTTPException,
    ) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: download from {tool.url} "
            f"failed: {error}"
        ) from error


def _verify_sha256(tool: Tool, archive: Path) -> None:
    digest = hashlib.sha256()
    try:
        with archive.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot read download: {error}"
        ) from error
    actual = digest.hexdigest()
    if actual != tool.sha256:
        raise GateError(
            f"tools: {tool.name} {tool.version}: sha256 mismatch: "
            f"expected {tool.sha256}, got {actual}; nothing installed"
        )


def _member_path(member: tarfile.TarInfo, tool: Tool) -> PurePosixPath:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise GateError(
            f"tools: {tool.name} {tool.version}: unsafe archive member "
            f"{member.name!r}; nothing installed"
        )
    return path


def _extract_archive(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            for member in members:
                _member_path(member, tool)
                if member.issym() or member.islnk():
                    raise GateError(
                        f"tools: {tool.name} {tool.version}: unsafe archive member "
                        f"{member.name!r} is a link; nothing installed"
                    )
                if member.isdir():
                    continue
                if not member.isreg():
                    raise GateError(
                        f"tools: {tool.name} {tool.version}: unsafe archive member "
                        f"{member.name!r} is not a regular file; nothing installed"
                    )
            for member in members:
                if not member.isreg():
                    continue
                relative = _member_path(member, tool)
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise GateError(
                        f"tools: {tool.name} {tool.version}: cannot read archive "
                        f"member {member.name!r}"
                    )
                with source, target.open("wb") as stream:
                    shutil.copyfileobj(source, stream)
                mode = member.mode & 0o777
                if mode:
                    os.chmod(target, mode)
    except (tarfile.TarError, OSError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract archive: {error}"
        ) from error


def _fetch_tool(tool: Tool, tools_root: Path) -> None:
    destination = tools_root / f"{tool.name}-{tool.version}"
    binary = _tool_binary(tool, tools_root)
    if binary.is_file():
        print(
            f"tools: {tool.name} {tool.version} already installed at {binary}"
        )
        return
    try:
        with tempfile.TemporaryDirectory(
            prefix=f".{tool.name}-{tool.version}-", dir=tools_root
        ) as temporary:
            temporary_path = Path(temporary)
            archive = temporary_path / "archive"
            _download(tool, archive)
            _verify_sha256(tool, archive)
            build = temporary_path / "build"
            build.mkdir()
            _extract_archive(archive, build, tool)
            installed_binary = build / tool.binary
            if not installed_binary.is_file():
                raise GateError(
                    f"tools: {tool.name} {tool.version}: archive does not contain "
                    f"{tool.binary!r}; nothing installed"
                )
            mode = installed_binary.stat().st_mode & 0o777
            if not mode & 0o111:
                os.chmod(installed_binary, mode | 0o111)
            if destination.is_symlink() or destination.is_file():
                destination.unlink()
            elif destination.is_dir():
                shutil.rmtree(destination)
            os.replace(build, destination)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot install: {error}"
        ) from error
    print(f"tools: installed {tool.name} {tool.version} at {binary}")


def command_tools_fetch(lock: Path) -> int:
    try:
        tools = load_tools(lock)
    except UsageError as error:
        print(error, file=sys.stderr)
        return 2
    tools_root = _tools_dir()
    try:
        tools_root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        print(f"tools: cannot create {tools_root}: {error}", file=sys.stderr)
        return 1
    for name in sorted(tools):
        try:
            _fetch_tool(tools[name], tools_root)
        except GateError as error:
            print(error, file=sys.stderr)
            return 1
    return 0


def command_tools_path(lock: Path, name: str) -> int:
    try:
        tools = load_tools(lock)
    except UsageError as error:
        print(error, file=sys.stderr)
        return 2
    if name not in tools:
        known = ", ".join(sorted(tools)) or "none"
        print(
            f"tools: unknown tool {name!r}; pinned tools: {known}",
            file=sys.stderr,
        )
        return 2
    print(_tool_binary(tools[name], _tools_dir()))
    return 0


def _jscpd_binary() -> Path:
    lock = _default_lock_path()
    tools = load_tools(lock)
    tool = tools.get("jscpd")
    if tool is None:
        raise GateError(f"{lock}: no [jscpd] tool is pinned")
    binary = _tool_binary(tool, _tools_dir())
    if not binary.is_file():
        raise GateError(
            f"jscpd {tool.version} is not installed at {binary}; "
            f"run '{TOOLS_FETCH}'"
        )
    return binary


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
            raise GateError(
                f"invalid SARIF report {report}: runs[{run_index}] is not an object"
            )
        results = run.get("results", [])
        if not isinstance(results, list):
            raise GateError(
                f"invalid SARIF report {report}: runs[{run_index}].results "
                "is not a list"
            )
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
                raise GateError(
                    f"invalid SARIF report {report}: {where} has malformed locations"
                )
            formatted: list[str] = []
            seen: set[str] = set()
            for location in [*locations, *related]:
                if not isinstance(location, dict):
                    raise GateError(
                        f"invalid SARIF report {report}: {where} has a "
                        "non-object location"
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
            )
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
        print(
            f"clones: [clones] is not configured in {config.path}",
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
    selected = sorted(
        relative
        for relative in files
        if classes.get(relative) in clone_config.classes
    )
    if not selected:
        classes_text = ", ".join(clone_config.classes) or "none"
        print(
            f"clones: no files in classes ({classes_text}); nothing to analyze",
            file=sys.stderr,
        )
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
            failures.append(
                f"baseline entry {entry.fingerprint}: empty reason ({detail})"
            )
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
            failures.append(
                f"new clone {fingerprint}: {', '.join(clone.locations)}"
            )

    for entry in resolved:
        print(
            f"clones: resolved {entry.fingerprint} "
            f"(files: {_format_files(entry.files)})"
        )

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


def command_check(root: Path, config: Config) -> int:
    results: list[tuple[str, int]] = []
    print("check: inventory", flush=True)
    inventory_code = command_inventory(root, config)
    results.append(("inventory", inventory_code))

    print("check: hygiene", flush=True)
    hygiene_code = command_hygiene(root, config)
    results.append(("hygiene", hygiene_code))

    if config.clones is not None:
        print("check: clones", flush=True)
        if inventory_code == 0:
            clones_code = command_clones(root, config)
        else:
            print(
                "clones: skipped because inventory failed", file=sys.stderr
            )
            clones_code = 1
        results.append(("clones", clones_code))

    failed = [name for name, code in results if code != 0]
    if failed:
        print(f"check: failed ({', '.join(failed)})", file=sys.stderr)
        return 1
    print(f"check: passed ({len(results)} checks)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qg.py",
        description="Inventory, hygiene, duplicate-code and tool checks.",
    )
    parser.add_argument(
        "--repo",
        metavar="DIR",
        help="top level of the git work tree (default: current directory)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser("inventory", help="classify every file")
    inventory.add_argument(
        "--list", dest="list_class", metavar="CLASS", help="print one class's files"
    )
    commands.add_parser("hygiene", help="check ignored and oversized files")
    clones = commands.add_parser("clones", help="check the duplicate-code ratchet")
    clones.add_argument(
        "--prune", action="store_true", help="remove resolved baseline entries"
    )
    tools = commands.add_parser("tools", help="manage pinned external tools")
    tool_commands = tools.add_subparsers(dest="tools_command", required=True)
    fetch = tool_commands.add_parser("fetch", help="download and verify pinned tools")
    fetch.add_argument("--lock", metavar="FILE", help="tool lock file")
    path = tool_commands.add_parser("path", help="print a pinned tool's binary")
    path.add_argument("name", metavar="NAME")
    commands.add_parser("check", help="run every configured check")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "tools":
        lock = (
            Path(args.lock).expanduser()
            if getattr(args, "lock", None)
            else _default_lock_path()
        )
        if args.tools_command == "fetch":
            return command_tools_fetch(lock)
        return command_tools_path(lock, args.name)

    try:
        root = resolve_repo(args.repo)
        config = load_config(root)
    except UsageError as error:
        print(error, file=sys.stderr)
        return error.exit_code

    if args.command == "inventory":
        return command_inventory(root, config, args.list_class)
    if args.command == "hygiene":
        return command_hygiene(root, config)
    if args.command == "clones":
        return command_clones(root, config, args.prune)
    return command_check(root, config)


if __name__ == "__main__":
    sys.exit(main())
