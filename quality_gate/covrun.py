#!/usr/bin/env python3
"""Start a Python program under the pinned coverage wheel.

Invoked by the python_tests adapter, and exported through QG_PYTHON, as:

    python -I covrun.py DATA_DIR SOURCE_ROOT COVERAGE_DIR ARGS...

DATA_DIR receives one coverage dataset per invocation plus the adapter's
registry; SOURCE_ROOT is the measured repository root, and COVERAGE_DIR is the
install directory of the pinned coverage wheel.  ARGS is a script or
'-m MODULE' plus its arguments.  The gate configuration is created once by the
python_tests adapter and every child consumes it.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quality_gate.coverage_tool import coverage_config_path, registry_dir
from quality_gate.policy import UnsupportedError
from quality_gate.tools import verify_tool_directory

sys.dont_write_bytecode = True


def _fail(message: str) -> int:
    print(f"covrun: {message}", file=sys.stderr)
    return 2


def _usage() -> int:
    return _fail(
        "expected DATA_DIR SOURCE_ROOT COVERAGE_DIR and a Python command, "
        "for example: covrun.py DIR ROOT COVERAGE -m unittest discover -s tests"
    )


def _remove_overrides() -> None:
    for name in list(os.environ):
        if name.startswith("COVERAGE_") and name != "COVERAGE_CORE":
            del os.environ[name]


def _program(command: list[str]) -> str:
    if command[0] == "-m":
        return " ".join(command[:2])
    return command[0]


def _register(data_dir: Path, dataset: str, program: str) -> None:
    directory = registry_dir(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    invocation = uuid.uuid4().hex
    temporary = directory / f"{invocation}.tmp"
    temporary.write_text(
        json.dumps({"dataset": dataset, "program": program}),
        encoding="utf-8",
    )
    temporary.replace(directory / f"{invocation}.json")


def _coverage_main(coverage_dir: Path):
    sys.dont_write_bytecode = True
    try:
        from coverage.cmdline import main as coverage_main
    except ImportError as error:
        return None, (
            f"cannot import coverage from {coverage_dir}: {error}; "
            "run 'python3 -I qg.py tools fetch'"
        )
    return coverage_main, None


def _run_dataset(
    data_dir: Path,
    source_root: Path,
    config_file: Path,
    coverage_main,
    command: list[str],
) -> int:
    dataset = f".coverage.{uuid.uuid4().hex}"
    _register(data_dir, dataset, _program(command))
    data_file = data_dir / dataset
    return coverage_main(
        [
            "run",
            f"--data-file={data_file}",
            f"--source={source_root}",
            f"--rcfile={config_file}",
            *command,
        ]
    )


def _prepared(
    argv: list[str],
) -> tuple[Path, Path, Path, Path, list[str]]:
    data_dir = Path(argv[1])
    source_root = Path(argv[2])
    coverage_dir = Path(argv[3])
    command = argv[4:]
    if not coverage_dir.is_dir():
        raise UnsupportedError(
            f"coverage is not installed at {coverage_dir}; "
            "run 'python3 -I qg.py tools fetch'"
        )
    verify_tool_directory("coverage", coverage_dir)
    config_file = coverage_config_path(data_dir)
    if not config_file.is_file():
        raise UnsupportedError(
            f"coverage configuration is missing at {config_file}; "
            "the python_tests adapter creates it"
        )
    return data_dir, source_root, coverage_dir, config_file, command


def _run(argv: list[str]) -> int:
    if len(argv) < 5:
        return _usage()
    try:
        data_dir, source_root, coverage_dir, config_file, command = _prepared(
            argv
        )
    except UnsupportedError as error:
        return _fail(str(error))

    sys.path.insert(0, str(coverage_dir))
    # A consumer's coverage configuration must not change this metric: line
    # coverage only, with no branch measurement or omit rules of its own.
    _remove_overrides()
    os.environ["COVERAGE_CORE"] = "sysmon"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    coverage_main, error = _coverage_main(coverage_dir)
    if error is not None:
        return _fail(error)
    assert coverage_main is not None
    return _run_dataset(
        data_dir, source_root, config_file, coverage_main, command
    )


if __name__ == "__main__":
    sys.exit(_run(sys.argv))
