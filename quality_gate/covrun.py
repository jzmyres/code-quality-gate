#!/usr/bin/env python3
"""Start a Python program under the pinned coverage wheel.

Invoked by the python_tests adapter, and exported through QG_PYTHON, as:

    python -I covrun.py DATA_DIR SOURCE_ROOT COVERAGE_DIR VERSION PAYLOAD_SHA256
        CONFIG_FILE REGISTRY_DIR ARGS...

DATA_DIR receives one coverage dataset per invocation; SOURCE_ROOT is the
measured repository root; COVERAGE_DIR is the install directory of the pinned
coverage wheel, which must match VERSION and PAYLOAD_SHA256 from the effective
tool lock; CONFIG_FILE is the gate-owned coverage configuration; and
REGISTRY_DIR receives the invocation records.  ARGS is a script or
'-m MODULE' plus its arguments.  The adapter creates the configuration once
and every child consumes it.

This runner imports nothing from quality_gate: importing the gate would leave
its package in the measured program's sys.modules and shadow the program's own
package of the same name.  The payload verifier is loaded from its file by path
for the same reason.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

_NOTHING_RUNS = (
    "nothing from this install runs; run 'python3 -I qg.py tools fetch'"
)


class _RunError(Exception):
    """A runner argument or pinned-install error."""


def _fail(message: str) -> int:
    print(f"covrun: {message}", file=sys.stderr)
    return 2


def _usage() -> int:
    return _fail(
        "expected DATA_DIR SOURCE_ROOT COVERAGE_DIR VERSION PAYLOAD_SHA256 "
        "CONFIG_FILE REGISTRY_DIR and a Python command, for example: "
        "covrun.py DIR ROOT COVERAGE VERSION PAYLOAD CONFIG REGISTRY "
        "-m unittest discover -s tests"
    )


def _payload_verifier():
    path = Path(__file__).with_name("payload.py")
    spec = importlib.util.spec_from_file_location("_qg_payload_digest", path)
    if spec is None or spec.loader is None:
        raise _RunError(f"cannot load the payload verifier at {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except OSError as error:
        raise _RunError(
            f"cannot load the payload verifier at {path}: {error}"
        ) from error
    return module


def _verify_coverage(
    coverage_dir: Path, version: str, payload_sha256: str
) -> None:
    verifier = _payload_verifier()
    try:
        actual = verifier.payload_digest(coverage_dir)
    except verifier.PayloadError as error:
        raise _RunError(
            f"coverage {version}: payload tree at {coverage_dir} is invalid: "
            f"{error}; expected {payload_sha256}, got invalid; "
            f"{_NOTHING_RUNS}"
        ) from error
    if actual != payload_sha256:
        raise _RunError(
            f"coverage {version}: payload digest mismatch at {coverage_dir}: "
            f"expected {payload_sha256}, got {actual}; {_NOTHING_RUNS}"
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
    version = argv[4]
    payload_sha256 = argv[5]
    config_file = Path(argv[6])
    registry = Path(argv[7])
    command = argv[8:]
    if not coverage_dir.is_dir():
        raise _RunError(
            f"coverage is not installed at {coverage_dir}; "
            "run 'python3 -I qg.py tools fetch'"
        )
    _verify_coverage(coverage_dir, version, payload_sha256)
    if not config_file.is_file():
        raise _RunError(
            f"coverage configuration is missing at {config_file}; "
            "the python_tests adapter creates it"
        )
    return data_dir, source_root, coverage_dir, config_file, registry, command


def _run(argv: list[str]) -> int:
    if len(argv) < 9:
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
