"""Load and combine data from the pinned coverage wheel.

The core is standard library only.  These helpers run only for the Python
adapters, and they put the tools cache's coverage install on sys.path first.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

from .policy import GateError, UnsupportedError
from .tools import installed_tool_dir


COVERAGE_CONFIG_NAME = "coverage.ini"
REGISTRY_NAME = "registry"
PRAGMA_NO_COVER = "pragma: no cover"


def coverage_config_text(root: Path) -> str:
    """The one gate-owned coverage configuration for collection and analysis."""
    return (
        "[run]\n"
        "branch = False\n"
        f"source =\n    {root}\n"
        "[report]\n"
        f"exclude_lines =\n    {PRAGMA_NO_COVER}\n"
    )


def coverage_config_path(data_dir: Path) -> Path:
    return data_dir / COVERAGE_CONFIG_NAME


def write_coverage_config(data_dir: Path, root: Path) -> Path:
    path = coverage_config_path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(coverage_config_text(root), encoding="utf-8")
    except OSError as error:
        raise GateError(
            f"cannot write coverage configuration at {path}: {error}"
        ) from error
    return path


def coverage_installation() -> Path:
    """The pinned coverage install directory, or UnsupportedError naming fetch."""
    return installed_tool_dir("coverage")


def import_coverage() -> ModuleType:
    """Import the pinned coverage module after putting its install on sys.path."""
    installation = coverage_installation()
    location = str(installation)
    if location not in sys.path:
        sys.path.insert(0, location)
    try:
        import coverage
    except ImportError as error:
        raise UnsupportedError(
            f"coverage at {installation} cannot be imported: {error}; "
            "run 'python3 -I qg.py tools fetch'"
        ) from error

    return coverage


def registry_dir(data_dir: Path) -> Path:
    """The directory where coverage invocations register themselves."""
    return data_dir / REGISTRY_NAME


def _valid_dataset_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and Path(name).name == name
    )


def _dataset_names(path: Path, document: object) -> list[str]:
    names = document.get("datasets") if isinstance(document, dict) else None
    if not isinstance(names, list) or not names:
        raise UnsupportedError(
            f"coverage registry record {path} has no usable dataset list"
        )
    for name in names:
        if not _valid_dataset_name(name):
            raise UnsupportedError(
                f"coverage registry record {path} names an unsafe dataset "
                f"{name!r}"
            )
    return names


def _read_completed(path: Path) -> list[str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise UnsupportedError(
            f"coverage registry record {path} is unreadable: {error}"
        ) from error
    return _dataset_names(path, document)


def registered_datasets(data_dir: Path) -> list[Path]:
    """Every dataset a registered invocation says it finalized."""
    directory = registry_dir(data_dir)
    started = sorted(directory.glob("*.started"))
    if not started:
        raise UnsupportedError(
            f"no coverage invocation registered in {directory}"
        )
    datasets: list[Path] = []
    for record in started:
        invocation = record.name.removesuffix(".started")
        completion = directory / f"{invocation}.json"
        if not completion.is_file():
            raise UnsupportedError(
                f"coverage invocation {invocation} did not finalize"
            )
        for name in _read_completed(completion):
            datasets.append(data_dir / name)
    return datasets


def _check_datasets(datasets: list[Path]) -> None:
    coverage = import_coverage()
    for path in datasets:
        if not path.is_file():
            raise UnsupportedError(f"coverage dataset {path} is missing")
        try:
            coverage.CoverageData(str(path)).read()
        except coverage.CoverageException as error:
            raise UnsupportedError(
                f"coverage dataset {path} is corrupt: {error}"
            ) from error


def combine_coverage(
    data_dir: Path,
    combined_file: Path,
    config_file: Path | None = None,
) -> None:
    """Combine every registered dataset under DATA_DIR into COMBINED_FILE."""
    coverage = import_coverage()
    _check_datasets(registered_datasets(data_dir))
    combined_file.parent.mkdir(parents=True, exist_ok=True)
    config = (
        config_file
        if config_file is not None
        else coverage_config_path(data_dir)
    )
    cover = coverage.Coverage(
        data_file=str(combined_file), config_file=str(config)
    )
    try:
        cover.combine(data_paths=[str(data_dir)], strict=True)
        cover.save()
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot combine coverage data from {data_dir}: {error}"
        ) from error
