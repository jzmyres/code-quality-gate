#!/usr/bin/env python3
"""Start a Python program under the pinned coverage wheel.

Invoked by the python_tests adapter, and exported through QG_PYTHON, as:

    python -I covrun.py DATA_DIR SOURCE_ROOT COVERAGE_DIR CONFIG_FILE REGISTRY_DIR ARGS...

DATA_DIR receives one coverage dataset per invocation; SOURCE_ROOT is the
measured repository root; COVERAGE_DIR is the install directory of the pinned
coverage wheel; CONFIG_FILE is the gate-owned coverage configuration; and
REGISTRY_DIR receives the invocation records.  ARGS is a script or
'-m MODULE' plus its arguments.  The adapter creates the configuration once
and every child consumes it.

This runner imports nothing from quality_gate: importing the gate would leave
its package in the measured program's sys.modules and shadow the program's own
package of the same name.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

_VERIFY_INSTALL = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from quality_gate.tools import verify_tool_directory

try:
    verify_tool_directory("coverage", Path(sys.argv[2]))
except Exception as error:
    print(error, file=sys.stderr)
    sys.exit(2)
"""


class _RunError(Exception):
    """A runner argument or pinned-install error."""


def _fail(message: str) -> int:
    print(f"covrun: {message}", file=sys.stderr)
    return 2


def _usage() -> int:
    return _fail(
        "expected DATA_DIR SOURCE_ROOT COVERAGE_DIR CONFIG_FILE REGISTRY_DIR "
        "and a Python command, for example: "
        "covrun.py DIR ROOT COVERAGE CONFIG REGISTRY -m unittest discover -s tests"
    )


def _verify_coverage(coverage_dir: Path) -> None:
    # The gate imports coverage in the parent; verify the install again here
    # without loading the gate into this interpreter.
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            _VERIFY_INSTALL,
            str(root),
            str(coverage_dir),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise _RunError(
            result.stderr.strip() or "cannot verify the coverage install"
        )


def _remove_overrides() -> None:
    for name in list(os.environ):
        if name.startswith("COVERAGE_") and name != "COVERAGE_CORE":
            del os.environ[name]


def _program(command: list[str]) -> str:
    if command[0] == "-m":
        return " ".join(command[:2])
    return command[0]


def _register(registry: Path, dataset: str, program: str) -> None:
    registry.mkdir(parents=True, exist_ok=True)
    invocation = uuid.uuid4().hex
    temporary = registry / f"{invocation}.tmp"
    temporary.write_text(
        json.dumps({"dataset": dataset, "program": program}),
        encoding="utf-8",
    )
    temporary.replace(registry / f"{invocation}.json")


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
    registry: Path,
    coverage_main,
    command: list[str],
) -> int:
    dataset = f".coverage.{uuid.uuid4().hex}"
    _register(registry, dataset, _program(command))
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
) -> tuple[Path, Path, Path, Path, Path, list[str]]:
    data_dir = Path(argv[1])
    source_root = Path(argv[2])
    coverage_dir = Path(argv[3])
    config_file = Path(argv[4])
    registry = Path(argv[5])
    command = argv[6:]
    if not coverage_dir.is_dir():
        raise _RunError(
            f"coverage is not installed at {coverage_dir}; "
            "run 'python3 -I qg.py tools fetch'"
        )
    _verify_coverage(coverage_dir)
    if not config_file.is_file():
        raise _RunError(
            f"coverage configuration is missing at {config_file}; "
            "the python_tests adapter creates it"
        )
    return data_dir, source_root, coverage_dir, config_file, registry, command


def _run(argv: list[str]) -> int:
    if len(argv) < 7:
        return _usage()
    # A consumer's coverage configuration must not change this metric: line
    # coverage only, with no branch measurement or omit rules of its own.
    _remove_overrides()
    try:
        (
            data_dir,
            source_root,
            coverage_dir,
            config_file,
            registry,
            command,
        ) = _prepared(argv)
    except _RunError as error:
        return _fail(str(error))

    sys.path.insert(0, str(coverage_dir))
    os.environ["COVERAGE_CORE"] = "sysmon"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    coverage_main, error = _coverage_main(coverage_dir)
    if error is not None:
        return _fail(error)
    assert coverage_main is not None
    return _run_dataset(
        data_dir,
        source_root,
        config_file,
        registry,
        coverage_main,
        command,
    )


if __name__ == "__main__":
    sys.exit(_run(sys.argv))
