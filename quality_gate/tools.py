"""Pinned tool locks, installation and binary lookup.

The lock validator derives its supported formats from the extraction dispatch.
"""
from __future__ import annotations

import contextlib
import ctypes
import fnmatch
import hashlib
import http.client
import lzma
import os
import re
import shutil
import stat
import struct
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

from .json_input import load_json
from .payload import PayloadError, _content_sha256, payload_digest
from .policy import GateError, UnsupportedError, UsageError, _describe, _string

TOOLS_FETCH = "python3 -I qg.py tools fetch"
TOOL_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
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


_CONDA_TARBALL = re.compile(r"(info|pkg)-([A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.zst)")
_CONDA_LAYOUT = "expected exactly metadata.json and matching info- and pkg-*.tar.zst members"
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_END = struct.Struct("<4s4H2LH")
_ZIP64_LOCATOR = struct.Struct("<4sLQL")
_ZIP64_END = struct.Struct("<4sQ2H2L4Q")
_ZIP_SIZE_LIMIT = 0xffffffff


def _conda_member_name(member: zipfile.ZipInfo) -> str:
    if member.orig_filename != member.filename:
        raise ValueError(f"invalid ZIP member name {member.orig_filename!r}")
    if (
        member.external_attr & 0x10
        or _member_kind(member, _WHEEL_MEMBER_KINDS) != _MEMBER_RULES["regular"]
    ):
        raise ValueError(f"ZIP member {member.filename!r} is not a regular file")
    return member.filename


def _conda_tar_members(archive: zipfile.ZipFile) -> tuple[str, str]:
    names = _conda_member_names(archive)
    tarballs = _conda_tarball_stems(names - {"metadata.json"})
    if "metadata.json" not in names or len(tarballs) != 2:
        raise ValueError(f"{_CONDA_LAYOUT}, found {', '.join(sorted(names)) or 'no members'}")
    payload = f"pkg-{tarballs['pkg']}"
    info = f"info-{tarballs['info']}"
    if tarballs["info"] != tarballs["pkg"]:
        raise ValueError(f"{_CONDA_LAYOUT}, unexpected ZIP member {info!r} for {payload!r}")
    return info, payload


def _conda_member_names(archive: zipfile.ZipFile) -> set[str]:
    names: set[str] = set()
    for member in archive.infolist():
        name = _conda_member_name(member)
        if name in names:
            raise ValueError(f"{_CONDA_LAYOUT}, duplicate ZIP member {name!r}")
        names.add(name)
    return names


def _conda_tarball_stems(names: set[str]) -> dict[str, str]:
    tarballs: dict[str, str] = {}
    for name in sorted(names):
        match = _CONDA_TARBALL.fullmatch(name)
        if match is None or match[1] in tarballs:
            raise ValueError(f"{_CONDA_LAYOUT}, unexpected ZIP member {name!r}")
        tarballs[match[1]] = match[2]
    return tarballs


def _conda_zip64_directory(stream: BinaryIO, end: int) -> tuple[int, int, int] | None:
    locator_offset = end - _ZIP64_LOCATOR.size
    stream.seek(locator_offset)
    signature, disk, offset, disks = _ZIP64_LOCATOR.unpack(stream.read(_ZIP64_LOCATOR.size))
    if signature != b"PK\x06\x07":
        return None
    if (disk, disks) != (0, 1) or offset + _ZIP64_END.size > locator_offset:
        raise ValueError("invalid ZIP64 end locator")
    stream.seek(offset)
    signature, size, _, _, disk, start_disk, count, total, length, start = (
        _ZIP64_END.unpack(stream.read(_ZIP64_END.size))
    )
    actual = (signature, offset + 12 + size, disk, start_disk, count, start + length)
    if actual != (b"PK\x06\x06", locator_offset, 0, 0, total, offset):
        raise ValueError("invalid ZIP64 central directory framing")
    return start, length, count


def _conda_zip_directory(stream: BinaryIO, comment: bytes) -> tuple[int, int, int]:
    end = stream.seek(-(_ZIP_END.size + len(comment)), os.SEEK_END)
    signature, disk, start_disk, count, total, length, start, comment_size = (
        _ZIP_END.unpack(stream.read(_ZIP_END.size))
    )
    if (signature, comment_size) != (b"PK\x05\x06", len(comment)):
        raise ValueError("invalid ZIP end record or trailing data")
    if (disk, start_disk, count) != (0, 0, total):
        raise ValueError("invalid ZIP central directory framing")
    zip64 = _conda_zip64_directory(stream, end)
    if zip64 is not None:
        return zip64
    if start + length != end:
        raise ValueError("invalid ZIP central directory framing")
    return start, length, count


def _conda_zip_descriptor(member: zipfile.ZipInfo, data: bytes) -> bool:
    short = struct.pack("<LLL", member.CRC, member.compress_size, member.file_size) if (
        max(member.compress_size, member.file_size) <= _ZIP_SIZE_LIMIT
    ) else None
    long = struct.pack("<LQQ", member.CRC, member.compress_size, member.file_size)
    if len(data) in (16, 24) and data.startswith(b"PK\x07\x08"):
        data = data[4:]
    return data in (short, long)


def _conda_zip_local(stream: BinaryIO, member: zipfile.ZipInfo, boundary: int) -> None:
    stream.seek(member.header_offset)
    header = stream.read(_ZIP_LOCAL_HEADER.size)
    if len(header) != _ZIP_LOCAL_HEADER.size:
        raise ValueError(f"{member.filename}: truncated local ZIP header")
    signature, _, flags, method, _, _, crc, packed, unpacked, name_size, extra_size = (
        _ZIP_LOCAL_HEADER.unpack(header)
    )
    actual = (signature, flags, method, stream.read(name_size))
    expected = (b"PK\x03\x04", member.flag_bits, member.compress_type, member.filename.encode("ascii"))
    if actual != expected:
        raise ValueError(f"{member.filename}: invalid local ZIP header")
    extra = stream.read(extra_size)
    _validate_conda_zip_local_sizes(member, (crc, packed, unpacked), extra)
    end = stream.tell() + member.compress_size
    if not _conda_zip_member_fits(stream, member, end, boundary):
        raise ValueError(f"{member.filename}: invalid ZIP member boundaries")


def _conda_zip_extra_fields(extra: bytes, name: str) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 0
    while offset < len(extra):
        if len(extra) - offset < 4:
            raise ValueError(f"{name}: truncated ZIP extra field")
        kind, size = struct.unpack_from("<HH", extra, offset)
        start = offset + 4
        offset = start + size
        if offset > len(extra):
            raise ValueError(f"{name}: truncated ZIP extra field")
        fields[kind] = extra[start:offset]
    return fields


def _validate_conda_zip_local_sizes(
    member: zipfile.ZipInfo, local: tuple[int, int, int], extra: bytes
) -> None:
    fields = _conda_zip_extra_fields(extra, member.filename)
    try:
        local = _conda_zip_local_values(local, fields)
    except (KeyError, struct.error) as error:
        raise ValueError(f"{member.filename}: invalid local ZIP64 sizes") from error
    expected = (member.CRC, member.compress_size, member.file_size)
    if member.flag_bits & 8:
        local = tuple(value or pinned for value, pinned in zip(local, expected, strict=True))
    if local != expected:
        raise ValueError(f"{member.filename}: local ZIP CRC or sizes disagree with central directory")


def _conda_zip_local_values(
    local: tuple[int, int, int], fields: dict[int, bytes]
) -> tuple[int, int, int]:
    crc, packed, unpacked = local
    if _ZIP_SIZE_LIMIT not in (packed, unpacked):
        return local
    unpacked, packed = _conda_zip64_sizes(unpacked, packed, fields[1])
    return crc, packed, unpacked


def _conda_zip_member_sizes(member: zipfile.ZipInfo) -> None:
    if member.compress_type != zipfile.ZIP_STORED:
        raise ValueError(f"{member.filename}: conda v2 requires stored ZIP members")
    if member.compress_size != member.file_size:
        raise ValueError(f"{member.filename}: invalid sizes for a stored ZIP member")
    _conda_zip_extra_fields(member.extra, member.filename)


def _conda_zip64_sizes(unpacked: int, packed: int, extra: bytes) -> tuple[int, int]:
    offset = 0
    if unpacked == _ZIP_SIZE_LIMIT:
        unpacked, = struct.unpack_from("<Q", extra)
        offset = 8
    if packed == _ZIP_SIZE_LIMIT:
        packed, = struct.unpack_from("<Q", extra, offset)
    return unpacked, packed


def _conda_zip_member_fits(
    stream: BinaryIO, member: zipfile.ZipInfo, end: int, boundary: int
) -> bool:
    if not member.flag_bits & 8:
        return end == boundary
    stream.seek(end)
    size = boundary - end
    return 12 <= size <= 24 and _conda_zip_descriptor(member, stream.read(size))


def _validate_conda_zip(stream: BinaryIO, archive: zipfile.ZipFile) -> None:
    """Account for container bytes outside the member streams checked by zipfile."""
    members = sorted(archive.infolist(), key=lambda member: member.header_offset)
    if members[0].header_offset != 0:
        raise ValueError("unexpected data before first ZIP member")
    start, length, count = _conda_zip_directory(stream, archive.comment)
    directory_size = sum(
        46 + len(member.filename) + len(member.extra) + len(member.comment) for member in members
    )
    if (count, length) != (len(members), directory_size):
        raise ValueError("invalid ZIP central directory length or member count")
    boundaries = [member.header_offset for member in members[1:]] + [start]
    for member, boundary in zip(members, boundaries, strict=True):
        _conda_zip_member_sizes(member)
        _conda_zip_local(stream, member, boundary)


def _validate_conda_metadata(archive: zipfile.ZipFile) -> None:
    metadata = load_json(archive.read("metadata.json").decode("utf-8"))
    version = metadata.get("conda_pkg_format_version") if isinstance(metadata, dict) else None
    if type(version) is not int or version != 2:
        raise ValueError("expected conda_pkg_format_version 2")


_TAR_BLOCK = tarfile.BLOCKSIZE
_PAX_LENGTH = re.compile(rb"[1-9][0-9]* ")
_PAX_RECORD = re.compile(rb"([^=\x00\n]+)=(.*)\n", re.DOTALL)
_PAX_TYPES = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)
_GNU_NAME_TYPES = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
_CONDA_HOOKS = (".*-pre-link.*", ".*-post-link.*", ".*-pre-unlink.*")


def _validate_conda_pax(data: bytes, offset: int) -> None:
    position = 0
    while position < len(data):
        match = _PAX_LENGTH.match(data, position)
        if match is None:
            raise ValueError(f"invalid PAX record at offset {offset + position}")
        end = position + int(match[0])
        if end > len(data):
            raise ValueError(f"invalid PAX record at offset {offset + position}")
        _validate_conda_pax_record(data[match.end():end], offset + position)
        position = end


def _validate_conda_pax_record(record: bytes, offset: int) -> None:
    match = _PAX_RECORD.fullmatch(record)
    if match is None:
        raise ValueError(f"invalid PAX record at offset {offset}")
    if match[1] == b"size" and not match[2].isdigit():
        raise ValueError(f"invalid PAX size at offset {offset}")


def _conda_tar_padding(fd: int, start: int, end: int) -> None:
    pad = os.pread(fd, end - start, start)
    if len(pad) != end - start or any(pad):
        raise ValueError(f"invalid tar member padding at offset {start}")


def _conda_tar_extensions(archive: tarfile.TarFile, offset: int, limit: int) -> None:
    fd = archive.fileobj.fileno()
    while offset < limit:
        header = tarfile.TarInfo.frombuf(
            os.pread(fd, _TAR_BLOCK, offset), archive.encoding, archive.errors
        )
        start = offset + _TAR_BLOCK
        end = start + header.size
        offset = end + (-header.size % _TAR_BLOCK)
        if header.size <= 0 or offset > limit:
            raise ValueError(f"invalid tar extension size at offset {start - _TAR_BLOCK}")
        _validate_conda_tar_extension(header.type, os.pread(fd, header.size, start), start)
        _conda_tar_padding(fd, end, offset)


def _validate_conda_tar_extension(kind: bytes, data: bytes, offset: int) -> None:
    if kind in _PAX_TYPES:
        _validate_conda_pax(data, offset)
    elif kind not in _GNU_NAME_TYPES or data.find(b"\0") != len(data) - 1:
        raise ValueError(f"invalid tar extension at offset {offset - _TAR_BLOCK}")


def _conda_tar_path(member: tarfile.TarInfo, tool: Tool) -> PurePosixPath:
    if not member.name or "\0" in member.name:
        raise ValueError(f"unsafe archive member {member.name!r}")
    path = _member_path(member.name, tool, root=member.isdir())
    _member_rule(_member_kind(member, _TAR_MEMBER_KINDS), member.name, tool)
    if member.sparse is not None:
        raise ValueError(f"unsafe archive member {member.name!r} is sparse")
    return path


def _conda_tar_member_end(
    archive: tarfile.TarFile, member: tarfile.TarInfo, header_offset: int
) -> int:
    end = member.offset_data + member.size
    aligned = end + (-member.size % _TAR_BLOCK)
    if member.size < 0 or aligned != archive.offset:
        raise ValueError(f"invalid size for {member.name!r} at offset {header_offset}")
    _conda_tar_padding(archive.fileobj.fileno(), end, aligned)
    return aligned


def _conda_tar_end(archive: tarfile.TarFile, offset: int) -> None:
    """Distinguish a valid terminator from tarfile stopping at a malformed header."""
    stream = archive.fileobj
    stream.seek(offset)
    blocks = stream.read(2 * _TAR_BLOCK)
    if any(blocks[:_TAR_BLOCK]):
        raise ValueError(f"invalid tar header at offset {offset}")
    if blocks != bytes(2 * _TAR_BLOCK):
        raise ValueError(f"expected two zero tar end blocks at offset {offset}")
    for padding in iter(lambda: stream.read(128 * 1024), b""):
        nonzero = padding.lstrip(b"\0")
        if nonzero:
            raise ValueError(f"nonzero data after tar end at offset {stream.tell() - len(nonzero)}")


def _conda_tar_records(
    archive: tarfile.TarFile, tool: Tool
) -> dict[PurePosixPath, tarfile.TarInfo]:
    records: dict[PurePosixPath, tarfile.TarInfo] = {}
    offset = 0
    try:
        for member in archive:
            path = _conda_tar_path(member, tool)
            if path in records:
                raise ValueError(f"duplicate normalized tar path {path!s} from {member.name!r}")
            records[path] = member
            _conda_tar_extensions(archive, offset, member.offset_data - _TAR_BLOCK)
            offset = _conda_tar_member_end(archive, member, offset)
    except (tarfile.TarError, ValueError, OSError, OverflowError) as error:
        raise ValueError(f"tar entry at offset {offset}: {error}") from error
    _conda_tar_end(archive, offset)
    return records


def _validate_conda_tar_parents(records: dict[PurePosixPath, tarfile.TarInfo]) -> None:
    files = {path for path, member in records.items() if member.isreg()}
    for path in records:
        for parent in path.parents:
            if parent in files:
                raise ValueError(f"tar entry {path!s} has regular file {parent!s} as a parent")


def _conda_hook(path: PurePosixPath) -> bool:
    return (
        len(path.parts) == 2
        and path.parts[0] in ("bin", "Scripts")
        and any(fnmatch.fnmatchcase(path.name, pattern) for pattern in _CONDA_HOOKS)
    )


def _write_conda_payload(
    archive: tarfile.TarFile,
    records: dict[PurePosixPath, tarfile.TarInfo],
    destination: Path,
) -> None:
    for path, member in records.items():
        if member.isdir() or _conda_hook(path):
            continue
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_member(
            target,
            archive.extractfile(member),
            member.mode & 0o777,
            f"cannot read tar entry {member.name!r}",
        )


@contextlib.contextmanager
def _conda_tar(
    archive: zipfile.ZipFile, member: str, staging: Path
) -> Iterator[tarfile.TarFile]:
    try:
        with archive.open(member) as source, tempfile.TemporaryFile(dir=staging) as tar:
            _decompress_zstd(source, tar)
            end = tar.tell()
            if end % _TAR_BLOCK:
                raise ValueError(f"truncated tar block at offset {end - end % _TAR_BLOCK}")
            tar.flush()
            tar.seek(0)
            try:
                parsed = tarfile.open(fileobj=tar, mode="r:")
            except (tarfile.TarError, ValueError, OverflowError, RecursionError) as error:
                raise ValueError(f"invalid tar header at offset 0: {error}") from error
            with parsed:
                yield parsed
    except (
        GateError, OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError,
        zlib.error, lzma.LZMAError, OverflowError,
    ) as error:
        raise ValueError(f"{member}: {error}") from error


def _extract_conda(archive_path: Path, destination: Path, tool: Tool) -> None:
    try:
        with archive_path.open("rb") as stream, zipfile.ZipFile(stream) as archive:
            info, payload = _conda_tar_members(archive)
            _validate_conda_zip(stream, archive)
            try:
                _validate_conda_metadata(archive)
            except (ValueError, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error,
                    lzma.LZMAError) as error:
                raise ValueError(f"metadata.json: {error}") from error
            with _conda_tar(archive, info, destination.parent) as tar:
                _validate_conda_tar_parents(_conda_tar_records(tar, tool))
            with _conda_tar(archive, payload, destination.parent) as tar:
                records = _conda_tar_records(tar, tool)
                _validate_conda_tar_parents(records)
                _write_conda_payload(tar, records, destination)
    except (
        zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError,
        zlib.error, lzma.LZMAError, struct.error,
    ) as error:
        raise GateError(
            f"tools: {tool.name} {tool.version}: cannot extract conda archive: {error}"
        ) from error


_ARCHIVE_EXTRACTORS = {"tar": _extract_tar, "wheel": _extract_wheel, "deb": _extract_deb}
_CONDA_FORMAT = "conda"
ARCHIVE_FORMATS = (*_ARCHIVE_EXTRACTORS, _CONDA_FORMAT)


def _extract_archive(archive_path: Path, destination: Path, tool: Tool) -> None:
    if tool.format == _CONDA_FORMAT:
        _extract_conda(archive_path, destination, tool)
        return
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


def _check_payload_path(root: Path, path: Path, *, missing_ok: bool = False) -> None:
    try:
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError:
            if not missing_ok:
                raise
            resolved = path.resolve()
    except (OSError, RuntimeError) as error:
        raise PayloadError(f"cannot resolve {path}: {error}") from error
    if not resolved.is_relative_to(root):
        raise PayloadError(f"{path} resolves outside the install directory {root}")


def _check_tree_paths(root: Path, directory: Path) -> None:
    pending = [directory]
    while pending:
        with os.scandir(pending.pop()) as children:
            for entry in children:
                path = Path(entry.path)
                _check_payload_path(root, path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)


def _check_payload_paths(tool: Tool, directory: Path) -> None:
    root = directory.resolve()
    component = directory
    for part in PurePosixPath(tool.binary).parts:
        component /= part
        _check_payload_path(root, component, missing_ok=True)
    if tool.format != "deb":
        _check_tree_paths(root, directory)


def _check_tool(tool: Tool, tools_root: Path) -> None:
    directory = _install_target(tool, tools_root)
    try:
        if directory.is_dir():
            _check_payload_paths(tool, directory)
    except (OSError, PayloadError, RuntimeError) as error:
        raise UnsupportedError(
            f"{tool.name} {tool.version}: payload tree at {directory} is invalid: {error}"
        ) from error
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
