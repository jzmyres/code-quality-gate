"""Load and combine data from the pinned coverage wheel.

The core is standard library only.  These helpers run only for the Python
adapters, and they put the tools cache's coverage install on sys.path first.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

from .policy import GateError, UnsupportedError
from .tools import installed_tool_dir


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


def combine_coverage(data_dir: Path, combined_file: Path) -> None:
    """Combine every parallel data file under DATA_DIR into COMBINED_FILE."""
    coverage = import_coverage()
    combined_file.parent.mkdir(parents=True, exist_ok=True)
    cover = coverage.Coverage(data_file=str(combined_file), config_file=False)
    try:
        cover.combine(data_paths=[str(data_dir)], strict=True)
        cover.save()
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot combine coverage data from {data_dir}: {error}"
        ) from error
