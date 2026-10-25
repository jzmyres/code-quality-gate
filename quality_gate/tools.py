"""Pinned tool locks, installation and binary lookup."""
from __future__ import annotations

import hashlib
import http.client
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .policy import GateError, UnsupportedError, UsageError, _describe, _string

TOOLS_FETCH = "python3 -I qg.py tools fetch"
TOOL_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
LOCK_KEYS = ("version", "url", "sha256", "binary", "format")


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str
    sha256: str
    binary: str
    format: str = "tar"


def _default_lock_path() -> Path:
    return Path(__file__).resolve().parent.parent / "tools.lock.toml"


def _tools_dir() -> Path:
    configured = os.environ.get("QG_TOOLS_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "share" / "code-quality-gate" / "tools"


def _tool_error(lock: Path, key: str, expected: str, actual: str) -> UsageError:
    return UsageError(f"{lock}: {key}: expected {expected}, got {actual}")


def _safe_relative_binary(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(path.parts) and not path.is_absolute() and ".." not in path.parts


def _lock_version(lock: Path, name: str, raw: dict[str, Any]) -> str:
    version = _string(raw, "version", lock, f"{name}.version")
    if TOOL_COMPONENT.fullmatch(version) is None:
        raise _tool_error(
            lock,
            f"{name}.version",
            "a version matching [A-Za-z0-9][A-Za-z0-9._-]*",
            _describe(version),
        )
    return version


def _lock_digest(lock: Path, name: str, raw: dict[str, Any]) -> str:
    digest = _string(raw, "sha256", lock, f"{name}.sha256")
    if len(digest) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in digest
    ):
        raise _tool_error(
            lock,
            f"{name}.sha256",
            "a 64-character hexadecimal SHA-256",
            _describe(digest),
        )
    return digest


def _lock_binary(lock: Path, name: str, raw: dict[str, Any]) -> str:
    binary = _string(raw, "binary", lock, f"{name}.binary")
    if not _safe_relative_binary(binary):
        raise _tool_error(
            lock,
            f"{name}.binary",
            "a safe relative path",
            _describe(binary),
        )
    return binary


def _lock_format(lock: Path, name: str, raw: dict[str, Any]) -> str:
    archive_format = raw.get("format", "tar")
    if archive_format not in ("tar", "wheel"):
        raise _tool_error(
            lock,
            f"{name}.format",
            "one of tar, wheel",
            _describe(archive_format),
        )
    return archive_format


def _parse_tool(lock: Path, name: str, raw: Any) -> Tool:
    if not isinstance(raw, dict):
        raise _tool_error(lock, name, "a table", _describe(raw))
    for key in raw:
        if key not in LOCK_KEYS:
            raise _tool_error(
                lock,
                f"{name}.{key}",
                f"a known key ({', '.join(LOCK_KEYS)}); "
                "allowed keys: " + ", ".join(LOCK_KEYS),
                "unknown key",
            )
    return Tool(
        name=name,
        version=_lock_version(lock, name, raw),
        url=_string(raw, "url", lock, f"{name}.url"),
        sha256=_lock_digest(lock, name, raw).lower(),
        binary=_lock_binary(lock, name, raw),
        format=_lock_format(lock, name, raw),
    )


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
        if TOOL_COMPONENT.fullmatch(name) is None:
            raise _tool_error(
                lock,
                name,
                "a tool name matching [A-Za-z0-9][A-Za-z0-9._-]*",
                _describe(name),
            )
        tools[name] = _parse_tool(lock, name, raw)
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


def _unsafe_member(tool: Tool, name: str) -> GateError:
    return GateError(
        f"tools: {tool.name} {tool.version}: unsafe archive member "
        f"{name!r}; nothing installed"
    )


def _member_path(member: tarfile.TarInfo, tool: Tool) -> PurePosixPath:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise _unsafe_member(tool, member.name)
    return path


def _extract_tar(archive_path: Path, destination: Path, tool: Tool) -> None:
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


def _wheel_member_path(member: zipfile.ZipInfo, tool: Tool) -> PurePosixPath:
    path = PurePosixPath(member.filename)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise _unsafe_member(tool, member.filename)
    mode = member.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise GateError(
            f"tools: {tool.name} {tool.version}: unsafe archive member "
            f"{member.filename!r} is a link; nothing installed"
        )
    if member.is_dir() or stat.S_ISDIR(mode):
        return path
    file_type = stat.S_IFMT(mode)
    if file_type not in (0, stat.S_IFREG):
        raise GateError(
            f"tools: {tool.name} {tool.version}: unsafe archive member "
            f"{member.filename!r} is not a regular file; nothing installed"
        )
    return path


def _extract_wheel(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            for member in members:
                _wheel_member_path(member, tool)
            for member in members:
                path = _wheel_member_path(member, tool)
                if member.is_dir() or stat.S_ISDIR(member.external_attr >> 16):
                    continue
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as stream:
                    shutil.copyfileobj(source, stream)
                mode = (member.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(target, mode)
    except (zipfile.BadZipFile, OSError, EOFError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract archive: {error}"
        ) from error


def _extract_archive(archive_path: Path, destination: Path, tool: Tool) -> None:
    if tool.format == "wheel":
        _extract_wheel(archive_path, destination, tool)
    else:
        _extract_tar(archive_path, destination, tool)


def _install_target(tool: Tool, tools_root: Path) -> Path:
    destination = tools_root / f"{tool.name}-{tool.version}"
    root = tools_root.resolve()
    try:
        resolved = destination.resolve()
    except (OSError, RuntimeError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot resolve install "
            f"destination {destination}: {error}; nothing installed"
        ) from error
    if not resolved.is_relative_to(root):
        raise GateError(
            f"tools: {tool.name} {tool.version}: install destination "
            f"{destination} resolves outside the tools directory {root}; "
            "nothing installed"
        )
    return destination


def _replace_destination(build: Path, destination: Path) -> None:
    if destination.is_symlink() or destination.is_file():
        destination.unlink()
    elif destination.is_dir():
        shutil.rmtree(destination)
    os.replace(build, destination)


def _fetch_tool(tool: Tool, tools_root: Path) -> None:
    destination = _install_target(tool, tools_root)
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
            _replace_destination(build, destination)
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

def _pinned_tool(name: str) -> tuple[Path, Tool]:
    lock = _default_lock_path()
    tools = load_tools(lock)
    tool = tools.get(name)
    if tool is None:
        known = ", ".join(sorted(tools)) or "none"
        raise UnsupportedError(
            f"{lock}: unknown tool {name!r} (pinned tools: {known}); "
            f"run '{TOOLS_FETCH}'"
        )
    return lock, tool


def tool_binary(name: str) -> Path:
    _lock, tool = _pinned_tool(name)
    binary = _tool_binary(tool, _tools_dir())
    if not binary.is_file():
        raise UnsupportedError(
            f"{name} {tool.version} is not installed at {binary}; "
            f"run '{TOOLS_FETCH}'"
        )
    return binary


def installed_tool_dir(name: str) -> Path:
    """The install directory of a pinned tool, proven by its binary file."""
    _lock, tool = _pinned_tool(name)
    directory = _tools_dir() / f"{tool.name}-{tool.version}"
    binary = directory / tool.binary
    if not binary.is_file():
        raise UnsupportedError(
            f"{name} {tool.version} is not installed at {binary}; "
            f"run '{TOOLS_FETCH}'"
        )
    return directory


def _jscpd_binary() -> Path:
    return tool_binary("jscpd")
