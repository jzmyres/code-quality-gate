"""Interpreters loaded by the kernel when an executable starts."""
from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO


def _script_interpreter(data: bytes) -> str:
    words = data[2:].split(b"\n", 1)[0].strip().split(None, 1)
    if not words:
        raise ValueError("empty script interpreter")
    return os.fsdecode(words[0])


def _unpack(data: bytes, offset: int, code: str, endian: str) -> int:
    try:
        return int(struct.unpack_from(endian + code, data, offset)[0])
    except struct.error as error:
        raise ValueError("truncated ELF header") from error


def _elf_layout(data: bytes) -> tuple[str, bool]:
    classes = {1: False, 2: True}
    byte_orders = {1: "<", 2: ">"}
    try:
        return byte_orders[data[5]], classes[data[4]]
    except (KeyError, IndexError) as error:
        raise ValueError("invalid ELF class or byte order") from error


_LAYOUTS = {
    False: (28, "I", 42, 44, 32, 4, 16),
    True: (32, "Q", 54, 56, 56, 8, 32),
}


def _elf_table(data: bytes, endian: str, is_64: bool) -> tuple[int, int, int]:
    phoff, word, sizeoff, countoff, minimum, _offset, _size = _LAYOUTS[is_64]
    offset = _unpack(data, phoff, word, endian)
    size = _unpack(data, sizeoff, "H", endian)
    count = _unpack(data, countoff, "H", endian)
    if count > 1024 or size < minimum:
        raise ValueError("invalid ELF program header table")
    return offset, size, count


def _elf_target(stream: BinaryIO, header: bytes, endian: str, is_64: bool) -> str:
    _phoff, word, _sizeoff, _countoff, _minimum, offset_pos, size_pos = _LAYOUTS[is_64]
    offset = _unpack(header, offset_pos, word, endian)
    size = _unpack(header, size_pos, word, endian)
    if not 1 < size <= 4096:
        raise ValueError("invalid ELF interpreter length")
    stream.seek(offset)
    value = stream.read(size)
    if len(value) != size or not value.endswith(b"\0"):
        raise ValueError("truncated ELF interpreter")
    return os.fsdecode(value[:-1])


def _elf_interpreter(stream: BinaryIO, data: bytes) -> str | None:
    endian, is_64 = _elf_layout(data)
    offset, size, count = _elf_table(data, endian, is_64)
    for index in range(count):
        stream.seek(offset + index * size)
        header = stream.read(size)
        if _unpack(header, 0, "I", endian) == 3:
            return _elf_target(stream, header, endian, is_64)
    return None


def interpreter(path: str) -> str | None:
    """Return the script or ELF interpreter named by an executable."""
    with Path(path).open("rb") as stream:
        data = stream.read(4096)
        if data.startswith(b"#!"):
            return _script_interpreter(data)
        if data.startswith(b"\x7fELF"):
            return _elf_interpreter(stream, data)
    raise ValueError("unknown executable format")
