"""Pinned tool locks, installation and binary lookup."""
from __future__ import annotations

import hashlib
import http.client
import os
import shutil
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .policy import GateError, UsageError, _describe, _string

TOOLS_FETCH = "python3 -I qg.py tools fetch"


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str
    sha256: str
    binary: str


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
