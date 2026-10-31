"""Load and combine data from the pinned coverage wheel.

The core is standard library only.  These helpers run only for the Python
adapters, and they put the tools cache's coverage install on sys.path first.
"""
from __future__ import annotations

import configparser
import errno
import os
import stat
import sys
from pathlib import Path
from types import ModuleType

from .json_input import load_json
from .policy import GateError, UnsupportedError, UsageError
from .tools import installed_tool_dir


COVERAGE_CONFIG_NAME = "coverage.ini"
REGISTRY_NAME = "registry"
PRAGMA_NO_COVER = "pragma: no cover"


def coverage_config_text(root: Path) -> str:
    """The one gate-owned coverage configuration for collection and analysis."""
    source = str(root)
    # Coverage splits commas/LF, substitutes variables and strips whitespace;
    # analysis also splits every str.splitlines() separator.
    for index, character in enumerate(source):
        if character in ",$\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029" or (
            character.isspace() and index in (0, len(source) - 1)
        ):
            raise UsageError(
                f"repository root {source!r} contains character {character!r}; "
                "coverage's 'source' setting cannot represent it unchanged"
            )
    return (
        "[run]\n"
        "branch = False\n"
        "sigterm = true\n"
        f"source =\n    {source}\n"
        "[report]\n"
        f"exclude_lines =\n    {PRAGMA_NO_COVER}\n"
    )


def _analysis_list(value: str) -> list[str]:
    """Read a list setting exactly as the analysis configuration does."""
    return [line.strip() for line in value.splitlines() if line.strip()]


def coverage_config_data(settings: str, data_file: Path) -> str:
    """The canonical configuration as coverage's in-memory `:data:` value."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(settings)
    install = import_coverage()
    config = install.config.CoverageConfig()
    config.set_option("run:branch", parser.getboolean("run", "branch"))
    config.set_option("run:sigterm", parser.getboolean("run", "sigterm"))
    config.set_option(
        "run:source",
        _analysis_list(parser.get("run", "source")),
    )
    config.set_option("run:data_file", str(data_file))
    config.set_option(
        "report:exclude_lines",
        _analysis_list(parser.get("report", "exclude_lines")),
    )
    config.post_process()
    return ":data:" + config.serialize()


def coverage_config_path(data_dir: Path) -> Path:
    return data_dir / COVERAGE_CONFIG_NAME


def _coverage_file_kind(mode: int) -> str:
    return {
        "d": "directory", "p": "FIFO", "l": "symlink", "s": "socket",
        "c": "character device", "b": "block device",
    }.get(stat.filemode(mode)[0], "non-regular file")


def _open_coverage_config(path: Path) -> int:
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise GateError("expected a regular file, got symlink") from error
        try:
            mode = path.lstat().st_mode
        except OSError:
            raise error from None
        if not stat.S_ISREG(mode):
            raise GateError(f"expected a regular file, got {_coverage_file_kind(mode)}") from error
        raise


def _read_coverage_config(path: Path) -> str:
    descriptor = _open_coverage_config(path)
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise GateError(f"expected a regular file, got {_coverage_file_kind(mode)}")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _coverage_config_problem(data_dir: Path, settings: str) -> str | None:
    path = coverage_config_path(data_dir)
    try:
        actual = _read_coverage_config(path)
    except GateError as error:
        return f"coverage configuration {path}: {error}"
    except (OSError, UnicodeDecodeError) as error:
        return f"coverage configuration {path} cannot be read: {error}"
    if actual != settings:
        return (
            f"coverage configuration {path} differs from the "
            "gate-owned configuration after the test run"
        )
    return None


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
    sys.dont_write_bytecode = True
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


def _registry_dataset(path: Path, document: object) -> str:
    dataset = document.get("dataset") if isinstance(document, dict) else None
    if dataset is None:
        raise UnsupportedError(
            f"coverage registry record {path} has no usable dataset"
        )
    if not _valid_dataset_name(dataset):
        raise UnsupportedError(
            f"coverage registry record {path} names an unsafe dataset "
            f"{dataset!r}"
        )
    return dataset


def _read_registration(path: Path) -> tuple[str, str]:
    try:
        document = load_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise UnsupportedError(
            f"coverage registry record {path} is unreadable: {error}"
        ) from error
    dataset = _registry_dataset(path, document)
    program = document.get("program", "") if isinstance(document, dict) else ""
    return dataset, str(program)


def registered_datasets(data_dir: Path) -> list[tuple[str, str, Path]]:
    """Every dataset a registered invocation will write."""
    directory = registry_dir(data_dir)
    records = sorted(directory.glob("*.json"))
    if not records:
        raise UnsupportedError(
            f"no coverage invocation registered in {directory}"
        )
    datasets: list[tuple[str, str, Path]] = []
    for record in records:
        dataset, program = _read_registration(record)
        datasets.append((record.stem, program, data_dir / dataset))
    return datasets


def _check_datasets(datasets: list[tuple[str, str, Path]]) -> None:
    coverage = import_coverage()
    for invocation, program, path in datasets:
        if not path.is_file():
            raise UnsupportedError(
                f"coverage invocation {invocation} ({program}) dataset "
                f"{path} is missing"
            )
        try:
            coverage.CoverageData(str(path)).read()
        except coverage.CoverageException as error:
            raise UnsupportedError(
                f"coverage invocation {invocation} ({program}) dataset "
                f"{path} is corrupt: {error}"
            ) from error


def combine_coverage(
    data_dir: Path,
    combined_file: Path,
    settings: str,
) -> None:
    """Combine every registered dataset under DATA_DIR into COMBINED_FILE."""
    coverage = import_coverage()
    _check_datasets(registered_datasets(data_dir))
    combined_file.parent.mkdir(parents=True, exist_ok=True)
    cover = coverage.Coverage(
        config_file=coverage_config_data(settings, combined_file)
    )
    try:
        cover.combine(data_paths=[str(data_dir)], strict=True)
        cover.save()
    except (coverage.CoverageException, OSError) as error:
        raise GateError(
            f"cannot combine coverage data from {data_dir}: {error}"
        ) from error
