"""Repository resolution, file enumeration, inventory and hygiene."""
from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .policy import Config, GateError, UsageError
from .runner import run


@dataclass(frozen=True)
class GitFile:
    path: str
    mode: str | None

    @property
    def gitlink(self) -> bool:
        return self.mode == "160000"


@dataclass(frozen=True)
class HygieneResult:
    ok: bool
    messages: list[str]
    summary: str
    execution: str = "completed"


def _git_toplevel(root: Path) -> str:
    result = run(
        [
            "git",
            "-c",
            f"safe.directory={root}",
            "-C",
            str(root),
            "rev-parse",
            "--show-toplevel",
        ],
        budget_seconds=600,
        capture_limit=None,
    )
    if result.execution == "error":
        raise UsageError(f"{root}: cannot run git: {result.error}")
    if result.execution != "completed":
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got "
            f"git {result.execution}"
        )
    if result.returncode != 0:
        detail = result.stderr_text.strip() or "git rev-parse failed"
        raise UsageError(
            f"{root}: expected the top level of a git work tree, got {detail}"
        )
    return result.stdout_text.strip()


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
    top = Path(_git_toplevel(root))
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
    result = run(command, budget_seconds=600, capture_limit=None)
    if result.execution == "error":
        raise GateError(f"{what} failed: {result.error}")
    if result.execution != "completed":
        raise GateError(f"{what} failed: git {result.execution}")
    if result.returncode != 0:
        detail = result.stderr_text.strip()
        raise GateError(f"{what} failed: {detail or f'git exited {result.returncode}'}")
    return result.stdout


def enumerate_entries(root: Path) -> list[GitFile]:
    raw = _git(
        root,
        ["ls-files", "-s", "-z", "-co", "--exclude-standard"],
        "file enumeration",
    )
    entries: list[GitFile] = []
    for token in raw.decode("utf-8", "surrogateescape").split("\0"):
        if not token:
            continue
        mode: str | None = None
        name = token
        if "\t" in token:
            metadata, candidate = token.split("\t", 1)
            fields = metadata.split()
            if (
                len(fields) == 3
                and len(fields[0]) == 6
                and fields[0].isdigit()
            ):
                mode = fields[0]
                name = candidate
        entries.append(GitFile(name, mode))
    return sorted(entries, key=lambda entry: entry.path)


def enumerate_files(root: Path) -> list[str]:
    return [entry.path for entry in enumerate_entries(root)]


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
    entries = enumerate_entries(root)
    files = [entry.path for entry in entries]
    gitlinks = {entry.path for entry in entries if entry.gitlink}
    matched = [0] * len(config.rules)
    classes: dict[str, str] = {}
    violations: list[str] = []
    known_classes = ", ".join(sorted(config.classes)) or "none"
    known_checks = ", ".join(config.checks) or "none"
    for name, class_def in config.classes.items():
        for check_id in class_def.checks:
            if check_id not in config.checks:
                violations.append(
                    f"classes.{name}: unknown check {check_id!r} "
                    f"(known checks: {known_checks})"
                )
        if not class_def.code:
            continue
        if not class_def.checks:
            violations.append(
                f"classes.{name}: code class lists no check "
                "(expected at least one check id)"
            )

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
        if relative in gitlinks:
            continue
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


def _ignored_tracked_files(root: Path) -> list[str]:
    raw = _git(
        root,
        ["ls-files", "-z", "-c", "-i", "--exclude-standard"],
        "ignored-file enumeration",
    )
    return [
        name
        for name in raw.decode("utf-8", "surrogateescape").split("\0")
        if name
    ]


def _size_violations(
    root: Path, entries: list[GitFile], max_bytes: int
) -> list[str]:
    violations: list[str] = []
    for entry in entries:
        if entry.gitlink:
            continue
        relative = entry.path
        try:
            size = (root / relative).stat().st_size
        except OSError as error:
            violations.append(
                f"hygiene: {relative}: cannot measure size: {error}"
            )
            continue
        if size > max_bytes:
            violations.append(
                f"hygiene: {relative}: {size} bytes exceeds max_bytes "
                f"{max_bytes}"
            )
    return violations


def hygiene_result(root: Path, config: Config) -> HygieneResult:
    try:
        ignored = _ignored_tracked_files(root)
        entries = enumerate_entries(root)
    except GateError as error:
        return HygieneResult(
            False,
            [f"hygiene: {error}"],
            "",
            execution="error",
        )
    if ignored:
        return HygieneResult(
            False,
            [
                f"hygiene: tracked file matches ignore rules: {relative}"
                for relative in ignored
            ],
            "",
        )
    violations = _size_violations(root, entries, config.max_bytes)
    if violations:
        return HygieneResult(False, violations, "")
    return HygieneResult(
        True,
        [],
        f"hygiene: {len(entries)} files within {config.max_bytes} bytes",
    )


def command_hygiene(root: Path, config: Config) -> int:
    result = hygiene_result(root, config)
    for message in result.messages:
        print(message, file=sys.stderr)
    if result.ok:
        print(result.summary)
    return 0 if result.ok else 1
