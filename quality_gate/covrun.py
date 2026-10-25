#!/usr/bin/env python3
"""Start a Python program under the pinned coverage wheel.

Invoked by the python_tests adapter, and exported through QG_PYTHON, as:

    python -I covrun.py DATA_DIR SOURCE_ROOT COVERAGE_DIR ARGS...

DATA_DIR receives parallel coverage data files, SOURCE_ROOT is the measured
repository root, and COVERAGE_DIR is the install directory of the pinned
coverage wheel.  ARGS is a script or '-m MODULE' plus its arguments.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


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


def _write_config(data_dir: Path, source_root: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    config_file = data_dir / "coverage.ini"
    config_file.write_text(
        "[run]\n"
        "branch = False\n"
        f"source =\n    {source_root}\n"
        "[report]\n"
        "exclude_lines =\n    pragma: no cover\n",
        encoding="utf-8",
    )
    os.environ["COVERAGE_RCFILE"] = str(config_file)
    return config_file


def _coverage_main(coverage_dir: Path):
    try:
        from coverage.cmdline import main as coverage_main
    except ImportError as error:
        return None, (
            f"cannot import coverage from {coverage_dir}: {error}; "
            "run 'python3 -I qg.py tools fetch'"
        )
    return coverage_main, None


def _run(argv: list[str]) -> int:
    if len(argv) < 5:
        return _usage()
    data_dir = Path(argv[1])
    source_root = Path(argv[2])
    coverage_dir = Path(argv[3])
    command = argv[4:]
    if not coverage_dir.is_dir():
        return _fail(
            f"coverage is not installed at {coverage_dir}; "
            "run 'python3 -I qg.py tools fetch'"
        )

    sys.path.insert(0, str(coverage_dir))
    # A consumer's coverage configuration must not change this metric: line
    # coverage only, with no branch measurement or omit rules of its own.
    _remove_overrides()
    os.environ["COVERAGE_CORE"] = "sysmon"
    config_file = _write_config(data_dir, source_root)

    coverage_main, error = _coverage_main(coverage_dir)
    if error is not None:
        return _fail(error)
    assert coverage_main is not None

    data_file = data_dir / ".coverage"
    return coverage_main(
        [
            "run",
            "--parallel-mode",
            f"--data-file={data_file}",
            f"--source={source_root}",
            f"--rcfile={config_file}",
            *command,
        ]
    )


if __name__ == "__main__":
    sys.exit(_run(sys.argv))
