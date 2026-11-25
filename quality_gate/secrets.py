from __future__ import annotations

import os
import shutil
import stat
import sys
from collections.abc import Callable, Iterable
from itertools import batched
from pathlib import Path
from typing import Any

_MAX_FILES_PER_INVOCATION = 24


def _copy_input(source: Path, destination: Path, relative: str) -> bool:
    mode = source.lstat().st_mode
    if stat.S_ISDIR(mode):
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(mode):
        destination.write_bytes(os.fsencode(source.readlink()))
    elif stat.S_ISREG(mode):
        shutil.copyfile(source, destination)
    else:
        raise ValueError(f"{relative}: expected a regular file or symlink")
    return True


def _snapshot(root: Path, directory: Path, selected: Iterable[str]) -> list[str]:
    paths = set()
    for relative in selected:
        source = root / relative
        if source.parent.resolve() != source.parent:
            continue
        if _copy_input(source, directory / relative, relative):
            paths.add(relative)
    return sorted(paths)


def scan(
    binary: Path, root: Path, directory: Path, selected: Iterable[str], budget: float,
    *, run: Callable[..., Any],
) -> Any:
    paths = _snapshot(root, directory, selected)
    argv = [
        str(binary), "dir", "--no-banner", "--no-color", "--verbose", "--legacy-print",
        "--redact=100", "--validation=false", "--unsafe-auto-load-config=false",
        "--gitleaks-ignore-path=/dev/null", "--ignore-gitleaks-allow", "--",
    ]
    failed = None
    for targets in batched(paths or ["."], _MAX_FILES_PER_INVOCATION):
        child = run(
            [*argv, *targets], cwd=directory, env={},
            budget_seconds=budget, capture_limit=None,
        )
        sys.stderr.buffer.write(child.stdout)
        sys.stderr.buffer.write(child.stderr)
        sys.stderr.buffer.flush()
        if child.execution != "completed":
            return child
        if child.returncode:
            failed = child
    return failed or child
