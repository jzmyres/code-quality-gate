"""Pinned tool locks, installation and binary lookup.

The lock validator and extraction dispatch share the archive format table.
"""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import http.client
import json
import lzma
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
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .payload import PayloadError, _content_sha256, payload_digest
from .policy import GateError, UnsupportedError, UsageError, _describe, _string

TOOLS_FETCH = "python3 -I qg.py tools fetch"
TOOL_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
ARCHIVE_FORMATS = ("tar", "wheel", "deb", "conda")
LOCK_KEYS = (
    "version",
    "url",
    "sha256",
    "payload_sha256",
    "binary",
    "format",
)


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str
    sha256: str
    payload_sha256: str
    binary: str
    format: str = "tar"


_LOCK_OVERRIDE: Path | None = None
_LOCK_TOOLS: dict[str, Tool] | None = None


def _default_lock_path() -> Path:
    if _LOCK_OVERRIDE is not None:
        return _LOCK_OVERRIDE
    return Path(__file__).resolve().parent.parent / "tools.lock.toml"


@contextlib.contextmanager
def lock_override(path: Path | None, tools: dict[str, Tool] | None = None):
    """Use PATH and its captured tool definitions for the duration of the block."""
    global _LOCK_OVERRIDE, _LOCK_TOOLS
    previous = _LOCK_OVERRIDE
    previous_tools = _LOCK_TOOLS
    _LOCK_OVERRIDE = path
    _LOCK_TOOLS = tools
    try:
        yield
    finally:
        _LOCK_OVERRIDE = previous
        _LOCK_TOOLS = previous_tools


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
            "a version matching [A-Za-z0-9][A-Za-z0-9._+-]*",
            _describe(version),
        )
    return version


def _lock_hex_digest(
    lock: Path, name: str, raw: dict[str, Any], key: str
) -> str:
    digest = _string(raw, key, lock, f"{name}.{key}")
    if len(digest) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in digest
    ):
        raise _tool_error(
            lock,
            f"{name}.{key}",
            "a 64-character hexadecimal SHA-256",
            _describe(digest),
        )
    return digest


def _lock_digest(lock: Path, name: str, raw: dict[str, Any]) -> str:
    return _lock_hex_digest(lock, name, raw, "sha256")


def _lock_payload_digest(lock: Path, name: str, raw: dict[str, Any]) -> str:
    return _lock_hex_digest(lock, name, raw, "payload_sha256")


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
    if archive_format not in ARCHIVE_FORMATS:
        raise _tool_error(
            lock,
            f"{name}.format",
            "one of " + ", ".join(ARCHIVE_FORMATS),
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
        payload_sha256=_lock_payload_digest(lock, name, raw).lower(),
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
                "a tool name matching [A-Za-z0-9][A-Za-z0-9._+-]*",
                _describe(name),
            )
        tools[name] = _parse_tool(lock, name, raw)
    return tools


def current_tools() -> tuple[Path, dict[str, Tool]]:
    """Return the active lock and the definitions fixed for this run."""
    if _LOCK_OVERRIDE is not None and _LOCK_TOOLS is not None:
        return _LOCK_OVERRIDE, dict(_LOCK_TOOLS)
    lock = _default_lock_path()
    return lock, load_tools(lock)


def _tool_binary(tool: Tool, tools_root: Path) -> Path:
    return tools_root / f"{tool.name}-{tool.version}" / tool.binary


def _payload_mismatch(
    tool: Tool, directory: Path, actual: str
) -> UnsupportedError:
    return UnsupportedError(
        f"{tool.name} {tool.version}: payload digest mismatch at {directory}: "
        f"expected {tool.payload_sha256}, got {actual}; nothing from this "
        f"install runs; run '{TOOLS_FETCH}'"
    )


def _tool_payload_digest(tool: Tool, directory: Path) -> str:
    """The digest the lock pins for this archive format.

    A debian package's payload is the declared binary itself, so its digest
    is the binary's content hash; other formats digest the whole install tree.
    """
    if tool.format == "deb":
        return _content_sha256(directory / tool.binary)
    return payload_digest(directory)


def _verify_tool_payload(tool: Tool, directory: Path) -> Path:
    binary = directory / tool.binary
    try:
        if not binary.is_file():
            raise UnsupportedError(
                f"{tool.name} {tool.version} is not installed at {binary}; "
                f"run '{TOOLS_FETCH}'"
            )
        actual = _tool_payload_digest(tool, directory)
    except (OSError, PayloadError) as error:
        raise UnsupportedError(
            f"{tool.name} {tool.version}: payload tree at {directory} is "
            f"invalid: {error}; expected {tool.payload_sha256}, got invalid; "
            f"nothing from this install runs; run '{TOOLS_FETCH}'"
        ) from error
    if actual != tool.payload_sha256:
        raise _payload_mismatch(tool, directory, actual)
    return directory


def verify_tool_directory(name: str, directory: Path) -> Path:
    """Verify an install directory against its pinned payload digest."""
    _lock, tool = _pinned_tool(name)
    return _verify_tool_payload(tool, directory)


def installed_tool(name: str) -> tuple[Tool, Path]:
    """The pinned tool and its verified install directory."""
    _lock, tool = _pinned_tool(name)
    directory = _tools_dir() / f"{tool.name}-{tool.version}"
    _verify_tool_payload(tool, directory)
    return tool, directory


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
            f"tools: {tool.name} {tool.version}: sha256 mismatch for {tool.url}: "
            f"expected {tool.sha256}, got {actual}; nothing installed"
        )


@dataclass(frozen=True)
class _MemberRule:
    writes: bool
    message: str = ""


_MEMBER_RULES = {
    "unsafe": _MemberRule(
        False, "unsafe archive member {name!r}; nothing installed"
    ),
    "link": _MemberRule(
        False,
        "unsafe archive member {name!r} is a link; nothing installed",
    ),
    "directory": _MemberRule(False),
    "regular": _MemberRule(True),
    "other": _MemberRule(
        False,
        "unsafe archive member {name!r} is not a regular file; "
        "nothing installed",
    ),
}

_ROOT_PATHS = (PurePosixPath("."), PurePosixPath("./"))

_TAR_MEMBER_KINDS = (
    (lambda member: member.issym(), _MEMBER_RULES["link"]),
    (lambda member: member.islnk(), _MEMBER_RULES["link"]),
    (lambda member: member.isdir(), _MEMBER_RULES["directory"]),
    (lambda member: member.isreg(), _MEMBER_RULES["regular"]),
)

_WHEEL_MEMBER_KINDS = (
    (
        lambda member: stat.S_ISLNK(member.external_attr >> 16),
        _MEMBER_RULES["link"],
    ),
    (
        lambda member: member.is_dir()
        or stat.S_ISDIR(member.external_attr >> 16),
        _MEMBER_RULES["directory"],
    ),
    (
        lambda member: stat.S_IFMT(member.external_attr >> 16)
        in (0, stat.S_IFREG),
        _MEMBER_RULES["regular"],
    ),
)


def _member_rule(rule: _MemberRule, name: str, tool: Tool) -> _MemberRule:
    if rule.message:
        raise GateError(
            f"tools: {tool.name} {tool.version}: "
            f"{rule.message.format(name=name)}"
        )
    return rule


def _member_kind(
    member: Any, kinds: tuple[tuple[Any, _MemberRule], ...]
) -> _MemberRule:
    return next(
        (rule for matches, rule in kinds if matches(member)),
        _MEMBER_RULES["other"],
    )


def _member_path(
    name: str, tool: Tool, *, root: bool = False
) -> PurePosixPath:
    path = PurePosixPath(name)
    if root and path in _ROOT_PATHS:
        return PurePosixPath()
    if path.is_absolute() or ".." in path.parts or not path.parts:
        _member_rule(_MEMBER_RULES["unsafe"], name, tool)
    return path


def _write_member(
    target: Path, source: Any, mode: int, missing: str
) -> None:
    if source is None:
        raise GateError(missing)
    with source, target.open("wb") as stream:
        shutil.copyfileobj(source, stream)
    if mode:
        os.chmod(target, mode)


def _extract_tar(
    archive_path: Path, destination: Path, tool: Tool, *, mode: str = "r:*"
) -> None:
    try:
        with tarfile.open(archive_path, mode) as archive:
            members = archive.getmembers()
            records = []
            for member in members:
                path = _member_path(
                    member.name, tool, root=member.isdir()
                )
                rule = _member_rule(
                    _member_kind(member, _TAR_MEMBER_KINDS),
                    member.name,
                    tool,
                )
                records.append((member, path, rule))
            for member, relative, rule in records:
                if not rule.writes:
                    continue
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_member(
                    target,
                    archive.extractfile(member),
                    member.mode & 0o777,
                    f"tools: {tool.name} {tool.version}: cannot read archive "
                    f"member {member.name!r}",
                )
    except (tarfile.TarError, OSError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract archive: {error}"
        ) from error


def _wheel_member_record(
    member: zipfile.ZipInfo, tool: Tool
) -> tuple[PurePosixPath, _MemberRule]:
    path = _member_path(member.filename, tool)
    rule = _member_rule(
        _member_kind(member, _WHEEL_MEMBER_KINDS),
        member.filename,
        tool,
    )
    return path, rule


def _wheel_member_path(member: zipfile.ZipInfo, tool: Tool) -> PurePosixPath:
    return _wheel_member_record(member, tool)[0]


def _extract_wheel(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            records = [
                (member, *_wheel_member_record(member, tool))
                for member in archive.infolist()
            ]
            for member, path, rule in records:
                if not rule.writes:
                    continue
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_member(
                    target,
                    archive.open(member),
                    (member.external_attr >> 16) & 0o777,
                    f"tools: {tool.name} {tool.version}: cannot read archive "
                    f"member {member.filename!r}",
                )
    except (zipfile.BadZipFile, OSError, EOFError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract archive: {error}"
        ) from error


def _ar_header(
    data: bytes, offset: int, tool: Tool
) -> tuple[str, int]:
    header = data[offset : offset + 60]
    if len(header) < 60:
        raise GateError(
            f"tools: {tool.name} {tool.version}: truncated ar header; "
            "nothing installed"
        )
    if header[58:60] != b"`\n":
        raise GateError(f"tools: {tool.name} {tool.version}: invalid ar header; nothing installed")
    try:
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: invalid ar header: "
            f"{error}; nothing installed"
        ) from error
    return name, size


def _ar_members(
    data: bytes, tool: Tool
) -> list[tuple[str, bytes]]:
    if not data.startswith(b"!<arch>\n"):
        raise GateError(
            f"tools: {tool.name} {tool.version}: not an ar archive; "
            "nothing installed"
        )
    members: list[tuple[str, bytes]] = []
    offset = 8
    while offset < len(data):
        name, size = _ar_header(data, offset, tool)
        offset += 60
        if size < 0 or offset + size > len(data):
            raise GateError(
                f"tools: {tool.name} {tool.version}: truncated ar member "
                f"{name!r}; nothing installed"
            )
        members.append((name, data[offset : offset + size]))
        offset += size + (size & 1)
    return members


def _debian_version(members: list[tuple[str, bytes]], tool: Tool) -> None:
    version = [raw for name, raw in members if name == "debian-binary"]
    if version != [b"2.0\n"]:
        raise GateError(
            f"tools: {tool.name} {tool.version}: expected debian-binary 2.0; "
            "nothing installed"
        )


def _debian_data(members: list[tuple[str, bytes]], tool: Tool) -> bytes:
    _debian_version(members, tool)
    data = [raw for name, raw in members if name.startswith("data.tar.")]
    if len(data) != 1:
        raise GateError(
            f"tools: {tool.name} {tool.version}: expected one data.tar member, "
            f"got {len(data)}; nothing installed"
        )
    return data[0]


def _extract_deb(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        members = _ar_members(archive_path.read_bytes(), tool)
        data = _debian_data(members, tool)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot read archive: {error}"
        ) from error
    temporary = tempfile.NamedTemporaryFile(
        prefix=".qg-data-", dir=destination.parent, delete=False
    )
    path = Path(temporary.name)
    try:
        with temporary:
            temporary.write(data)
        _extract_tar(path, destination, tool)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract archive: {error}"
        ) from error
    finally:
        path.unlink(missing_ok=True)


class _ZstdBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
        ("position", ctypes.c_size_t),
    ]


def _zstd_library() -> ctypes.CDLL:
    library = ctypes.CDLL("libzstd.so.1")
    buffer_pointer = ctypes.POINTER(_ZstdBuffer)
    signatures = (
        (library.ZSTD_createDStream, ctypes.c_void_p, []),
        (library.ZSTD_freeDStream, ctypes.c_size_t, [ctypes.c_void_p]),
        (
            library.ZSTD_decompressStream,
            ctypes.c_size_t,
            [ctypes.c_void_p, buffer_pointer, buffer_pointer],
        ),
        (library.ZSTD_isError, ctypes.c_uint, [ctypes.c_size_t]),
        (library.ZSTD_getErrorName, ctypes.c_char_p, [ctypes.c_size_t]),
    )
    for function, result, arguments in signatures:
        function.restype = result
        function.argtypes = arguments
    return library


def _zstd_chunk(
    library: ctypes.CDLL, context: int, chunk: bytes, target: BinaryIO,
    buffer: ctypes.Array,
) -> int:
    source = ctypes.create_string_buffer(chunk)
    incoming = _ZstdBuffer(ctypes.addressof(source), len(chunk), 0)
    outgoing = _ZstdBuffer(ctypes.addressof(buffer), len(buffer), 0)
    while True:
        outgoing.position = 0
        remaining = library.ZSTD_decompressStream(
            context, ctypes.byref(outgoing), ctypes.byref(incoming),
        )
        if library.ZSTD_isError(remaining):
            raise ValueError(library.ZSTD_getErrorName(remaining).decode("ascii"))
        target.write(buffer[:outgoing.position])
        if incoming.position == incoming.size and (
            remaining == 0 or outgoing.position < outgoing.size
        ):
            return remaining


def _decompress_zstd(source: BinaryIO, target: BinaryIO) -> None:
    library = _zstd_library()
    context = library.ZSTD_createDStream()
    if not context:
        raise ValueError("cannot allocate a Zstandard decoder")
    try:
        buffer = ctypes.create_string_buffer(128 * 1024)
        remaining = 1
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            remaining = _zstd_chunk(library, context, chunk, target, buffer)
        if remaining:
            raise ValueError("incomplete Zstandard frame")
    finally:
        library.ZSTD_freeDStream(context)


_CONDA_PAYLOAD = re.compile(r"pkg-([A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.zst)")


def _conda_member_name(member: zipfile.ZipInfo) -> str:
    if member.orig_filename != member.filename:
        raise ValueError(f"invalid ZIP member name {member.orig_filename!r}")
    if _member_kind(member, _WHEEL_MEMBER_KINDS) != _MEMBER_RULES["regular"]:
        raise ValueError(f"ZIP member {member.filename!r} is not a regular file")
    return member.filename


def _conda_tar_members(archive: zipfile.ZipFile) -> tuple[str, str]:
    names = sorted(_conda_member_name(member) for member in archive.infolist())
    expected = "expected exactly metadata.json and matching info- and pkg-*.tar.zst members"
    if len(names) != 3:
        raise ValueError(expected)
    info, marker, payload = names
    match = _CONDA_PAYLOAD.fullmatch(payload)
    if match is None or info != f"info-{match[1]}" or marker != "metadata.json":
        raise ValueError(expected)
    return info, payload


def _validate_conda_metadata(archive: zipfile.ZipFile) -> None:
    with archive.open("metadata.json") as stream:
        metadata = json.load(stream)
    version = metadata.get("conda_pkg_format_version") if isinstance(metadata, dict) else None
    if type(version) is not int or version != 2:
        raise ValueError("expected conda_pkg_format_version 2")


@contextlib.contextmanager
def _conda_tar(archive: zipfile.ZipFile, member: str, staging: Path) -> Iterator[Path]:
    with archive.open(member) as source, tempfile.NamedTemporaryFile(
        prefix=".qg-conda-", dir=staging
    ) as tar:
        _decompress_zstd(source, tar)
        if tar.tell() % tarfile.BLOCKSIZE:
            raise ValueError(f"{member}: truncated tar block")
        tar.flush()
        yield Path(tar.name)


def _extract_conda(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            info, payload = _conda_tar_members(archive)
            _validate_conda_metadata(archive)
            with _conda_tar(archive, info, destination.parent) as path, tarfile.open(path, "r:") as tar:
                tar.getmembers()
            with _conda_tar(archive, payload, destination.parent) as path:
                _extract_tar(path, destination, tool, mode="r:")
    except (
        zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError,
        zlib.error, lzma.LZMAError,
    ) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract conda archive: {error}"
        ) from error


_ARCHIVE_EXTRACTORS = dict(zip(
    ARCHIVE_FORMATS, (_extract_tar, _extract_wheel, _extract_deb, _extract_conda),
    strict=True,
))


def _extract_archive(archive_path: Path, destination: Path, tool: Tool) -> None:
    extractor = _ARCHIVE_EXTRACTORS.get(tool.format, _extract_tar)
    extractor(archive_path, destination, tool)


def _install_target(tool: Tool, tools_root: Path) -> Path:
    destination = tools_root / f"{tool.name}-{tool.version}"
    try:
        root = tools_root.resolve()
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


def _make_read_only(tool: Tool, directory: Path) -> None:
    """Remove every write bit from a verified payload tree."""
    try:
        for path in [directory, *directory.rglob("*")]:
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
                os.chmod(path, stat.S_IMODE(mode) & ~0o222)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot make payload at "
            f"{directory} read-only: {error}"
        ) from error


def _make_directories_writable(directory: Path) -> None:
    """Restore the owner's read, write and search bits on a tree's directories."""
    def unlock(path: Path) -> None:
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            os.chmod(path, stat.S_IMODE(mode) | 0o700)

    unlock(directory)
    for current, directories, _files in os.walk(directory):
        base = Path(current)
        for name in directories:
            unlock(base / name)


def _remove_install(destination: Path) -> None:
    try:
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        elif destination.is_dir():
            _make_directories_writable(destination)
            shutil.rmtree(destination)
    except OSError as error:
        raise GateError(
            f"tools: cannot remove install at {destination}: {error}"
        ) from error


def _replace_destination(build: Path, destination: Path) -> None:
    """Replace the installed payload and restore its read-only mode.

    Renaming a directory across parents requires its own write bit, so
    the payload root is writable only during the move.
    """
    _remove_install(destination)
    mode = stat.S_IMODE(build.lstat().st_mode)
    os.chmod(build, mode | stat.S_IWUSR)
    os.replace(build, destination)
    os.chmod(destination, mode & ~0o222)


def _existing_payload_matches(tool: Tool, destination: Path) -> bool:
    if not destination.is_dir():
        return False
    try:
        return _tool_payload_digest(tool, destination) == tool.payload_sha256
    except PayloadError:
        return False


def _build_install(tool: Tool, temporary_path: Path) -> Path:
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
    try:
        actual = _tool_payload_digest(tool, build)
    except PayloadError as error:
        raise UsageError(
            f"tools: {tool.name} {tool.version}: cannot read payload at "
            f"{build}: {error}; nothing installed"
        ) from error
    if actual != tool.payload_sha256:
        raise GateError(
            f"tools: {tool.name} {tool.version}: payload sha256 "
            f"mismatch: expected {tool.payload_sha256}, got {actual}; "
            "nothing installed"
        )
    _make_read_only(tool, build)
    return build


def _fetch_tool(tool: Tool, tools_root: Path) -> None:
    destination = _install_target(tool, tools_root)
    binary = _tool_binary(tool, tools_root)
    try:
        if _existing_payload_matches(tool, destination):
            _make_read_only(tool, destination)
            print(
                f"tools: {tool.name} {tool.version} already installed at "
                f"{binary}; made the payload read-only"
            )
            return
        with tempfile.TemporaryDirectory(
            prefix=f".{tool.name}-{tool.version}-", dir=tools_root
        ) as temporary:
            build = _build_install(tool, Path(temporary))
            _replace_destination(build, destination)
    except OSError as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot install: {error}"
        ) from error
    print(f"tools: installed {tool.name} {tool.version} at {binary}")


def _create_tools_root(tools_root: Path) -> None:
    try:
        tools_root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise GateError(f"tools: cannot create {tools_root}: {error}") from error


def _check_tool(tool: Tool, tools_root: Path) -> None:
    directory = _install_target(tool, tools_root)
    _verify_tool_payload(tool, directory)


def command_tools_fetch(lock: Path, *, check: bool = False) -> int:
    try:
        tools = load_tools(lock)
        tools_root = _tools_dir()
        if not check:
            _create_tools_root(tools_root)
        for name in sorted(tools):
            if check:
                _check_tool(tools[name], tools_root)
            else:
                _fetch_tool(tools[name], tools_root)
    except GateError as error:
        print(error, file=sys.stderr)
        return error.exit_code
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
    lock, tools = current_tools()
    tool = tools.get(name)
    if tool is None:
        known = ", ".join(sorted(tools)) or "none"
        raise UnsupportedError(
            f"{lock}: unknown tool {name!r} (pinned tools: {known}); "
            f"run '{TOOLS_FETCH}'"
        )
    return lock, tool


def tool_binary(name: str) -> Path:
    tool, directory = installed_tool(name)
    return directory / tool.binary


def installed_tool_dir(name: str) -> Path:
    """The verified install directory of a pinned tool."""
    _tool, directory = installed_tool(name)
    return directory
