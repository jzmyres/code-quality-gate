"""The canonical payload digest of an installed tool directory.

covrun.py loads this module by path, so the measured interpreter never imports
the gate package; tools.py imports it normally.  Only the standard library is
used here.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath


class PayloadError(Exception):
    """An install tree contains an entry that has no payload representation."""


def _content_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise PayloadError(f"cannot read {path}: {error}") from error
    return digest.hexdigest()


def _payload_mode(path: Path) -> int:
    try:
        return path.lstat().st_mode
    except OSError as error:
        raise PayloadError(f"cannot inspect {path}: {error}") from error


def _payload_link(path: Path, relative: str) -> list[str]:
    try:
        target = os.readlink(path)
    except OSError as error:
        raise PayloadError(f"cannot read link {path}: {error}") from error
    return ["symlink", relative, target]


def _payload_record(path: Path, relative: str) -> list[str]:
    mode = _payload_mode(path)
    if stat.S_ISLNK(mode):
        return _payload_link(path, relative)
    if stat.S_ISDIR(mode):
        return ["directory", relative]
    if stat.S_ISREG(mode):
        executable = "1" if mode & 0o111 else "0"
        return ["file", relative, executable, _content_sha256(path)]
    raise PayloadError(
        f"{relative!r} is not a regular file, directory or symlink"
    )


def _payload_entries(root: Path) -> list[tuple[str, list[str]]]:
    entries: list[tuple[str, list[str]]] = []
    pending: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath())]
    while pending:
        directory, prefix = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as error:
            raise PayloadError(f"cannot list {directory}: {error}") from error
        for child in children:
            relative = prefix / child.name
            record = _payload_record(Path(child.path), str(relative))
            entries.append((str(relative), record))
            if record[0] == "directory":
                pending.append((Path(child.path), relative))
    entries.sort(key=lambda item: item[0])
    return entries


def payload_digest(directory: Path) -> str:
    """The canonical SHA-256 of every entry under an install directory."""
    digest = hashlib.sha256()
    for _relative, record in _payload_entries(directory):
        line = json.dumps(record, separators=(",", ":")) + "\n"
        digest.update(line.encode("utf-8"))
    return digest.hexdigest()
