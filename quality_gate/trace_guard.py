"""Keep the tracer's private output descriptor out of reach of its tracees.

The pinned tracer is a dynamically linked Linux/amd64 executable.  Once it has
opened its output and before its child is released, the gate asks it to set
PR_SET_DUMPABLE to zero.  Ptrace executes an existing syscall instruction in
its libc and restores the stopped process's registers before detaching.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal
from pathlib import Path


class _Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi "
        "orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs"
    ).split()]


def _ptrace(request: int, pid: int, address: int = 0, data: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    result = libc.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return int(result)


def _syscall_address(pid: int) -> int:
    maps = Path(f"/proc/{pid}/maps").read_text(encoding="ascii").splitlines()
    region = next(line.split()[0] for line in maps if "r-xp" in line and "libc.so" in line)
    start, end = (int(number, 16) for number in region.split("-"))
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
        memory.seek(start)
        code = memory.read(end - start)
    return start + code.index(b"\x0f\x05")


def _is_stop(status: int, expected: int) -> bool:
    return os.WIFSTOPPED(status) and os.WSTOPSIG(status) == expected


def _step_tracer(pid: int) -> None:
    for _ in range(20):
        _ptrace(9, pid)  # PTRACE_SINGLESTEP
        _, status = os.waitpid(pid, 0)
        if _is_stop(status, signal.SIGTRAP):
            return
        if not _is_stop(status, signal.SIGCHLD):
            raise OSError(errno.EIO, f"tracer protection stopped unexpectedly: {status}")
    raise OSError(errno.EIO, "tracer protection did not finish")


def _run_prctl(pid: int, saved: _Registers) -> None:
    registers = _Registers.from_buffer_copy(saved)
    registers.rip = _syscall_address(pid)
    registers.rax, registers.orig_rax = 157, (1 << 64) - 1
    registers.rdi, registers.rsi, registers.rdx = 4, 0, 0
    registers.r10, registers.r8 = 0, 0
    _ptrace(13, pid, 0, ctypes.addressof(registers))
    _step_tracer(pid)
    _ptrace(12, pid, 0, ctypes.addressof(registers))
    if registers.rax != 0:
        raise OSError(errno.EPERM, "tracer could not become non-dumpable")


def protect_tracer(pid: int) -> None:
    if platform.machine() != "x86_64":
        raise OSError(errno.ENOTSUP, "the pinned tracer requires Linux amd64")
    _ptrace(16, pid)  # PTRACE_ATTACH
    try:
        _, status = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(status):
            raise OSError(errno.EIO, "cannot stop tracer")
        saved = _Registers()
        _ptrace(12, pid, 0, ctypes.addressof(saved))
        _run_prctl(pid, saved)
        _ptrace(13, pid, 0, ctypes.addressof(saved))
    finally:
        _ptrace(17, pid)  # PTRACE_DETACH
