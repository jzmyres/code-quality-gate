"""Repository resolution, file enumeration, inventory and hygiene."""
from __future__ import annotations

import fnmatch
import subprocess
import sys
from pathlib import Path, PurePosixPath

from .policy import Config, GateError, UsageError


def resolve_repo(value: str | None) -> Path:
    raw = Path(value) if value is not None else Path.cwd()
    try:
        root = raw.resolve(strict=True)
    except OSError as error:
        raise UsageError(
            f"{raw}: expected the top level of a git work tree, got {error}"
        ) from error
    if not root.is_dir():
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got a non-directory"
        )
    command = [
        "git",
        "-c",
        f"safe.directory={root}",
        "-C",
        str(root),
        "rev-parse",
        "--show-toplevel",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as error:
        raise UsageError(f"{root}: cannot run git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or "git rev-parse failed"
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got {detail}"
        )
    top = Path(result.stdout.strip())
    try:
        top = top.resolve(strict=True)
    except OSError:
        pass
    if top != root:
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got {top}"
        )
    return root


def _git(root: Path, args: list[str], what: str) -> bytes:
    command = ["git", "-c", f"safe.directory={root}", "-C", str(root), *args]
    try:
        result = subprocess.run(command, capture_output=True)
    except OSError as error:
        raise GateError(f"{what} failed: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"{what} failed: {detail or f'git exited {result.returncode}'}")
    return result.stdout


def enumerate_files(root: Path) -> list[str]:
    raw = _git(
        root, ["ls-files", "-z", "-co", "--exclude-standard"], "file enumeration"
    )
    names = raw.decode("utf-8", "surrogateescape").split("\0")
    return sorted(name for name in names if name)


def _shebang_interpreter(first_line: str) -> str | None:
    if not first_line.startswith("#!"):
        return None
    words = first_line[2:].strip().split()
    if not words:
        return None
    name = PurePosixPath(words[0]).name
    if name != "env":
        return name
    index = 1
    while index < len(words):
        word = words[index]
        if word.startswith("-") or "=" in word:
            index += 1
            continue
        break
    if index >= len(words):
        return None
    return PurePosixPath(words[index]).name


def _is_code(path: Path, relative: str, config: Config) -> bool:
    if any(
        fnmatch.fnmatchcase(relative, pattern)
        for pattern in config.code_patterns
    ):
        return True
    if not config.code_shebangs:
        return False
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        interpreter = _shebang_interpreter(stream.readline())
    if interpreter is None:
        return False
    return any(
        fnmatch.fnmatchcase(interpreter, pattern)
        for pattern in config.code_shebangs
    )


def validate_inventory(
    root: Path, config: Config
) -> tuple[list[str], dict[str, str], list[str]]:
    files = enumerate_files(root)
    matched = [0] * len(config.rules)
    classes: dict[str, str] = {}
    violations: list[str] = []
    known_classes = ", ".join(sorted(config.classes)) or "none"

    for rule in config.rules:
        if not rule.pattern:
            violations.append(
                f"rule[{rule.index}]: empty pattern (expected a non-empty pattern)"
            )
        if not rule.reason.strip():
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): "
                "empty reason (expected a non-empty reason)"
            )
        if rule.class_name not in config.classes:
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): "
                f"unknown class {rule.class_name!r} (known classes: {known_classes})"
            )

    for relative in files:
        hits = [
            (index, rule)
            for index, rule in enumerate(config.rules)
            if fnmatch.fnmatchcase(relative, rule.pattern)
        ]
        for index, _rule in hits:
            matched[index] += 1
        if not hits:
            violations.append(f"{relative}: unclassified (no rule matches)")
            continue
        if len(hits) > 1:
            patterns = ", ".join(repr(rule.pattern) for _index, rule in hits)
            violations.append(
                f"{relative}: matches {len(hits)} rules ({patterns})"
            )
            continue
        rule = hits[0][1]
        class_def = config.classes.get(rule.class_name)
        if class_def is None:
            continue
        classes[relative] = rule.class_name
        try:
            code = _is_code(root / relative, relative, config)
        except OSError as error:
            violations.append(f"{relative}: cannot read shebang: {error}")
            continue
        if code and not class_def.code:
            violations.append(
                f"{relative}: code file classified as {rule.class_name!r} "
                f"(rule {rule.pattern!r})"
            )

    for index, rule in enumerate(config.rules):
        if matched[index] == 0:
            violations.append(
                f"rule[{rule.index}] (pattern {rule.pattern!r}): matches no file"
            )
    return files, classes, violations


def command_inventory(
    root: Path, config: Config, list_class: str | None = None
) -> int:
    if list_class is not None and list_class not in config.classes:
        known = ", ".join(sorted(config.classes)) or "none"
        print(
            f"inventory: unknown class {list_class!r}; known classes: {known}",
            file=sys.stderr,
        )
        return 2
    try:
        files, classes, violations = validate_inventory(root, config)
    except GateError as error:
        print(f"inventory: {error}", file=sys.stderr)
        return 1
    if violations:
        for violation in violations:
            print(f"inventory: {violation}", file=sys.stderr)
        return 1
    if list_class is not None:
        for relative in sorted(classes):
            if classes[relative] == list_class:
                print(relative)
        return 0
    print(f"inventory: {len(files)} files match {len(config.rules)} rules")
    return 0


def command_hygiene(root: Path, config: Config) -> int:
    try:
        raw = _git(
            root,
            ["ls-files", "-z", "-c", "-i", "--exclude-standard"],
            "ignored-file enumeration",
        )
        ignored = [
            name
            for name in raw.decode("utf-8", "surrogateescape").split("\0")
            if name
        ]
        if ignored:
            for relative in ignored:
                print(
                    f"hygiene: tracked file matches ignore rules: {relative}",
                    file=sys.stderr,
                )
            return 1
        files = enumerate_files(root)
    except GateError as error:
        print(f"hygiene: {error}", file=sys.stderr)
        return 1

    violations: list[str] = []
    for relative in files:
        try:
            size = (root / relative).stat().st_size
        except OSError as error:
            violations.append(f"{relative}: cannot measure size: {error}")
            continue
        if size > config.max_bytes:
            violations.append(
                f"{relative}: {size} bytes exceeds max_bytes {config.max_bytes}"
            )
    if violations:
        for violation in violations:
            print(f"hygiene: {violation}", file=sys.stderr)
        return 1
    print(f"hygiene: {len(files)} files within {config.max_bytes} bytes")
    return 0
