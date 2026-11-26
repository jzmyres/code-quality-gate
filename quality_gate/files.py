"""Repository resolution, file enumeration, inventory and hygiene.

BUILTIN_RESULT_KINDS is the shared set of results reported on every
check run. The runner, decision rule and command dispatch all read it.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import stat
import sys
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import product
from pathlib import Path, PurePosixPath

from .policy import Config, ConfigError, GateError, Rule, UsageError
from .runner import execution_outcome, run


SHEBANG_LIMIT = 4096
SOURCE_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".el": "lisp",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "jsx",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c-header",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".lisp": "lisp",
    ".clj": "clojure",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".lua": "lua",
    ".pl": "perl",
    ".r": "r",
    ".sql": "sql",
    ".md": "markdown",
    ".json": "json",
}
_INTERPRETER_LANGUAGE = dict.fromkeys(
    ("sh", "bash", "rbash", "dash", "ksh", "mksh", "posh"), "bash",
) | {"python": "python", "emacs": "lisp"}
_PYTHON_INTERPRETER = re.compile(r"python(?:3(?:\.[0-9]+)?)?")
_INTERPRETER_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*$")
DIFF_BASE_ENV = "QG_DIFF_BASE"
STANDALONE_BUILTINS = ("inventory", "hygiene")
BUILTIN_RESULT_KINDS = (*STANDALONE_BUILTINS, "module-contracts")
_SHEBANG_ENV = "env"
_TYPE_NAMES = {
    stat.S_IFIFO: "FIFO",
    stat.S_IFSOCK: "socket",
    stat.S_IFCHR: "character device",
    stat.S_IFBLK: "block device",
}


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


def git_argv(root: Path, *args: str) -> list[str]:
    """The one invocation policy for git commands on a candidate repository."""
    return [
        "git",
        "--no-replace-objects",
        "-c",
        f"safe.directory={root}",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        *args,
    ]


def _git_toplevel(root: Path) -> str:
    result = run(
        git_argv(root, "rev-parse", "--show-toplevel"),
        budget_seconds=600,
        capture_limit=None,
    )
    outcome = execution_outcome(result.execution)
    if outcome.error:
        raise UsageError(f"{root}: cannot run git: {result.error}")
    if not outcome.completed:
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
    result = run(
        git_argv(root, *args), budget_seconds=600, capture_limit=None
    )
    outcome = execution_outcome(result.execution)
    if outcome.error:
        raise GateError(f"{what} failed: {result.error}")
    if not outcome.completed:
        raise GateError(f"{what} failed: git {result.execution}")
    if result.returncode != 0:
        detail = result.stderr_text.strip()
        raise GateError(f"{what} failed: {detail or f'git exited {result.returncode}'}")
    return result.stdout


@dataclass(frozen=True)
class DiffBase:
    """The commit a diff check judged from, and the value that named it."""

    commit: str
    source: str

    def measurement(self) -> dict[str, str]:
        return {"commit": self.commit, "source": self.source}


def _verified_commit(root: Path, value: str) -> tuple[str | None, str]:
    """The commit VALUE names, and why it does not when it names none."""
    checked = run(
        git_argv(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{value}^{{commit}}"),
        budget_seconds=600,
        capture_limit=None,
    )
    if checked.execution == "completed" and checked.returncode == 0:
        return checked.stdout_text.strip(), ""
    problem = (
        f"got git {checked.execution}"
        if checked.execution != "completed"
        else "got no such revision"
    )
    return None, problem


@dataclass(frozen=True)
class DiffBaseOverride:
    """A run's resolved diff base and any shared affected path selection."""

    base: DiffBase | None = None
    error: ConfigError | None = None
    changed_paths: frozenset[str] | None = None
    untracked_paths: frozenset[str] = frozenset()

    def for_scope(
        self, root: Path, policy_base: str, *, override: bool = True
    ) -> DiffBase:
        """The override for a scope that takes it, else the policy base."""
        if override:
            if self.error is not None:
                raise self.error
            if self.base is not None:
                return self.base
        commit, problem = _verified_commit(root, policy_base)
        if commit is None:
            raise GateError(
                f"base {policy_base!r}: expected an existing revision, {problem}"
            )
        return DiffBase(commit, "base")


def resolve_diff_base(root: Path) -> DiffBaseOverride:
    """Resolve QG_DIFF_BASE once, keeping a failure for each diff check."""
    value = os.environ.get(DIFF_BASE_ENV)
    if value is None:
        return DiffBaseOverride()
    if not value.strip():
        return DiffBaseOverride(
            error=ConfigError(
                f"{DIFF_BASE_ENV} {value!r}: expected a commit id, "
                "got an empty value"
            )
        )
    commit, problem = _verified_commit(root, value)
    if commit is None:
        return DiffBaseOverride(
            error=ConfigError(
                f"{DIFF_BASE_ENV} {value!r}: expected an existing commit, "
                f"{problem}"
            )
        )
    return DiffBaseOverride(base=DiffBase(commit, DIFF_BASE_ENV))


def diff_base(
    root: Path,
    policy_base: str,
    *,
    override: bool = True,
    resolved: DiffBaseOverride | None = None,
) -> DiffBase:
    """The commit a diff check judges from, once for every check that diffs.

    QG_DIFF_BASE names the change the caller judges: a runner's item base, a
    landing check's main commit, or CI's pushed base.  It replaces the policy
    base and never falls back to it, so an unusable value is an error.  A check
    whose scope judges the whole tree keeps its policy base.  A run passes its
    one RESOLVED value to every check, so a moving branch cannot change it.
    """
    choice = (
        resolved if resolved is not None else resolve_diff_base(root)
    )
    return choice.for_scope(root, policy_base, override=override)


def _staged_entries(root: Path) -> list[GitFile]:
    """Tracked and staged index records; only these carry a git mode."""
    raw = _git(
        root,
        ["ls-files", "-s", "-z"],
        "file enumeration",
    )
    entries: list[GitFile] = []
    for token in raw.decode("utf-8", "surrogateescape").split("\0"):
        if not token:
            continue
        metadata, _separator, name = token.partition("\t")
        fields = metadata.split()
        mode = fields[0] if fields else None
        entries.append(GitFile(name, mode))
    return entries


def _split_nul(raw: bytes) -> list[str]:
    return [
        name
        for name in raw.decode("utf-8", "surrogateescape").split("\0")
        if name
    ]


def changed_paths(root: Path, commit: str, operation: str) -> set[str]:
    names = set()
    for comparison in ([commit, "HEAD"], ["--cached"], []):
        names.update(_split_nul(_git(
            root, ["diff", "--name-only", "--no-renames", "-z", *comparison, "--"],
            operation,
        )))
    return names


def affected_diff(root: Path, revision: str) -> DiffBaseOverride:
    commit, problem = _verified_commit(root, revision)
    if commit is None:
        raise UsageError(f"check: --base {revision!r}: expected an existing commit, {problem}")
    operation = f"check: --base {revision!r}: changed-file selection"
    try:
        merge_base = _git(root, ["merge-base", commit, "HEAD"], operation).decode().strip()
        names = changed_paths(root, merge_base, operation)
        untracked = frozenset(_untracked_files(root, operation))
    except GateError as error:
        raise UsageError(str(error)) from error
    return DiffBaseOverride(
        base=DiffBase(merge_base, "--base"), changed_paths=untracked.union(names),
        untracked_paths=untracked,
    )


def _untracked_files(
    root: Path, what: str = "untracked-file selection"
) -> list[str]:
    return _split_nul(
        _git(
            root,
            ["ls-files", "--others", "--exclude-standard", "-z"],
            what,
        )
    )


def _untracked_entries(root: Path) -> list[GitFile]:
    return [
        GitFile(name, None)
        for name in _untracked_files(root, "file enumeration")
    ]


def _deleted_paths(root: Path) -> set[str]:
    raw = _git(
        root,
        ["ls-files", "--deleted", "-z"],
        "deleted-file enumeration",
    )
    return {
        name
        for name in raw.decode("utf-8", "surrogateescape").split("\0")
        if name
    }


def enumerate_entries(root: Path) -> list[GitFile]:
    """Enumerate repository entries, including gitlinks with no worktree entry.

    A gitlink names a commit rather than a file.
    """
    entries = _staged_entries(root)
    deleted = _deleted_paths(root)
    entries = [
        entry for entry in entries
        if entry.gitlink or entry.path not in deleted
    ]
    entries.extend(_untracked_entries(root))
    return sorted(entries, key=lambda entry: entry.path)


def enumerate_files(root: Path) -> list[str]:
    return [entry.path for entry in enumerate_entries(root)]


class _EnvArguments:
    def __init__(self, arguments: str | list[str]) -> None:
        self.raw = arguments.lstrip() if isinstance(arguments, str) else ""
        self.pending = deque(arguments if isinstance(arguments, list) else ())

    def read_word(self, *, split_string: bool = False) -> str | None:
        if self.raw:
            if split_string:
                payload, self.raw = self.raw, ""
                return payload
            word, *remaining = self.raw.split(maxsplit=1)
            self.raw = remaining[0] if remaining else ""
            return word
        return self.pending.popleft() if self.pending else None


def _consume_env_option(option: str, words: _EnvArguments, path: Path | str) -> None:
    if option in ("-u", "-C"):
        words.read_word()
    elif option in ("-S", "--split-string"):
        payload = words.read_word(split_string=True) or ""
        try:
            words.pending.extendleft(reversed(shlex.split(payload)))
        except ValueError as error:
            raise GateError(f"{path}: invalid shebang env {option!r} argument: {error}") from error
    else:
        raise GateError(f"{path}: unsupported shebang env option {option!r}")


def _env_operands(arguments: str | list[str], path: Path | str) -> Iterator[str]:
    words = _EnvArguments(arguments)
    while (word := words.read_word()) is not None:
        if word == "--":
            yield from iter(words.read_word, None)
            return
        name, separator, _ = word.partition("=")
        if name + separator in ("-i", "--ignore-environment", "-", "--unset=", "--chdir="):
            continue
        if word.startswith("-"):
            _consume_env_option(word, words, path)
        else:
            yield word


def _env_interpreter(arguments: str | list[str], path: Path | str = "<shebang>") -> str | None:
    for word in _env_operands(arguments, path):
        if "=" not in word:
            return PurePosixPath(word).name
    return None


def _shebang_interpreter(first_line: str, path: Path | str = "<shebang>") -> str | None:
    if not first_line.startswith("#!"):
        return None
    words = first_line[2:].split(maxsplit=1)
    if not words:
        return None
    name = PurePosixPath(words[0]).name
    if name != _SHEBANG_ENV:
        return name
    return _env_interpreter(words[1] if len(words) == 2 else "", path)


def _type_name(mode: int) -> str | None:
    return _TYPE_NAMES.get(stat.S_IFMT(mode))


def _entry_type(path: Path) -> str | None:
    return _type_name(path.lstat().st_mode)


def _shebang_line(path: Path) -> str:
    with path.open("rb") as stream:
        return _bounded_shebang(stream.read(SHEBANG_LIMIT))


def _bounded_shebang(data: bytes) -> str:
    return data[:SHEBANG_LIMIT].decode("utf-8", "replace").split("\n", 1)[0]


def _python_shebang(first_line: str, path: Path | str) -> bool:
    interpreter = _shebang_interpreter(first_line, path)
    return interpreter is not None and _PYTHON_INTERPRETER.fullmatch(interpreter) is not None


def is_python_blob(relative: str, data: bytes) -> bool:
    """Classify a regular Git blob by the same suffix and shebang as the worktree."""
    return relative.endswith(".py") or _python_shebang(_bounded_shebang(data), relative)


def is_python_program(root: Path, relative: str) -> bool:
    if relative.endswith(".py"):
        return True
    path = root / relative
    try:
        return stat.S_ISREG(path.lstat().st_mode) and _python_shebang(_shebang_line(path), path)
    except OSError as error:
        raise GateError(f"cannot read shebang of {relative}: {error}") from error


def _parent_fd(root: Path, relative: str) -> int:
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(relative).parts[:-1]:
            following = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = following
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def read_regular(root: Path, relative: str) -> bytes | None:
    parent = -1
    try:
        parent = _parent_fd(root, relative)
        name = PurePosixPath(relative).name
        if not stat.S_ISREG(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
            return None
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GateError(f"cannot scan {relative}: expected a regular file")
            return stream.read()
    except OSError as error:
        raise GateError(f"cannot scan {relative}: {error}") from error
    finally:
        if parent >= 0:
            os.close(parent)


@dataclass(frozen=True)
class SourceClassification:
    code: bool
    language: str | None
    deferred: bool = False


def _matches_patterns(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _configured_shebang_language(path: Path, patterns: tuple[str, ...]) -> str | None:
    name = _shebang_interpreter(_shebang_line(path), path) or ""
    interpreter = _INTERPRETER_VERSION.sub("", name)
    if _matches_patterns(interpreter, patterns):
        return _INTERPRETER_LANGUAGE.get(interpreter)
    return None


def _classify_link(
    path: Path, patterns: tuple[str, ...], code_by_path: bool, selected: bool,
) -> SourceClassification:
    if not selected:
        return SourceClassification(code_by_path, None, deferred=True)
    if path.is_file() and _configured_shebang_language(path, patterns) == "python":
        return SourceClassification(code_by_path, "python")
    return SourceClassification(code_by_path, None)


def source_language(
    path: Path, relative: str, config: Config, *, selected: bool = True,
) -> SourceClassification:
    """Classify a file by its configured interpreter first and its suffix second."""
    suffix = SOURCE_LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    code_by_path = _matches_patterns(relative, config.code_patterns)
    fallback = SourceClassification(code_by_path, suffix)
    patterns = config.code_shebangs
    if not patterns:
        return fallback
    mode = path.lstat().st_mode
    if stat.S_ISREG(mode):
        language = _configured_shebang_language(path, patterns)
        return fallback if language is None else SourceClassification(True, language)
    if suffix is None and stat.S_ISLNK(mode):
        return _classify_link(path, patterns, code_by_path, selected)
    return fallback


class InventoryClasses(dict[str, str]):
    """Inventory classes and the source languages decided alongside them."""

    def __init__(
        self, classes: dict[str, str], sources: dict[str, SourceClassification], tracked: set[str],
    ) -> None:
        super().__init__(classes)
        self.code_paths = frozenset(path for path, source in sources.items() if source.code)
        self.tracked_code_paths = self.code_paths & tracked
        self.languages: dict[str, str | None] = {}
        self.deferred_links: set[str] = set()
        for path, source in sources.items():
            if source.deferred:
                self.deferred_links.add(path)
            else:
                self.languages[path] = source.language


def _selected_language(root: Path, path: str, config: Config) -> str | None:
    try:
        return source_language(root / path, path, config).language
    except OSError as error:
        raise GateError(f"cannot read shebang of {path}: {error}") from error


def source_languages(
    root: Path, paths: list[str], config: Config, classes: dict[str, str],
) -> dict[str, str | None]:
    """Return recorded languages, resolving deferred links among selected paths."""
    if not isinstance(classes, InventoryClasses):
        return {path: _selected_language(root, path, config) for path in paths}
    for path in sorted(classes.deferred_links.intersection(paths)):
        classes.languages[path] = _selected_language(root, path, config)
        classes.deferred_links.remove(path)
    return {path: classes.languages.get(path) for path in paths}


def _reject_special_files(
    root: Path, entries: list[GitFile]
) -> tuple[list[GitFile], list[str]]:
    kept: list[GitFile] = []
    violations: list[str] = []
    for entry in entries:
        if entry.gitlink:
            kept.append(entry)
            continue
        try:
            kind = _entry_type(root / entry.path)
        except OSError as error:
            violations.append(f"{entry.path}: cannot inspect: {error}")
            continue
        if kind is not None:
            violations.append(
                f"{entry.path}: unsupported file type {kind} "
                "(expected a regular file or symlink)"
            )
            continue
        kept.append(entry)
    return kept, violations


def _known_names(names: Iterable[str]) -> str:
    return ", ".join(names) or "none"


_CLASS_MESSAGES = {
    (True, False): (
        "classes.{name}: code class lists no check "
        "(expected at least one check id)"
    ),
}

_FILE_CLASS_MESSAGES = {
    (True, False): (
        "{relative}: code file classified as {class_name} "
        "(rule {pattern})"
    ),
}

_FILE_HIT_MESSAGES = {
    0: "{relative}: unclassified (no rule matches)",
    1: None,
    2: "{relative}: matches {count} rules ({patterns})",
}

_RULE_CHECKS = (
    (
        lambda rule, config: not rule.pattern,
        "rule[{index}]: empty pattern (expected a non-empty pattern)",
    ),
    (
        lambda rule, config: not rule.reason.strip(),
        "rule[{index}] (pattern {pattern}): empty reason "
        "(expected a non-empty reason)",
    ),
    (
        lambda rule, config: rule.class_name not in config.classes,
        "rule[{index}] (pattern {pattern}): unknown class {class_name} "
        "(known classes: {known_classes})",
    ),
)

@dataclass
class _InventoryValidator:
    root: Path
    config: Config
    entries: list[GitFile]
    violations: list[str]
    matched: list[int]
    classes: dict[str, str]
    gitlinks: set[str]
    sources: dict[str, SourceClassification] = field(default_factory=dict)

    def validate(self) -> tuple[list[str], dict[str, str], list[str]]:
        files = [entry.path for entry in self.entries]
        self._check_classes()
        self._check_rules()
        self._classify_files()
        paths = set(files) - self.gitlinks
        outside: list[str] = []
        modules = self.config.module_dirs
        if modules is not None:
            outside = self._check_module_placement(paths, modules)
            self.violations.extend(_unused_module_violations(self.entries, self.gitlinks, modules))
        if self.config.shared_base is not None:
            for relative in sorted(paths.difference(self.classes, outside)):
                self._record_source(relative)
        self.violations.extend(_unused_rule_violations(self.config.rules, self.matched))
        classes = InventoryClasses(self.classes, self.sources, _tracked_paths(self.entries))
        return files, classes, self.violations

    def _check_classes(self) -> None:
        known = _known_names(self.config.checks)
        for name, class_def in self.config.classes.items():
            for check_id in class_def.checks:
                if check_id not in self.config.checks:
                    self.violations.append(
                        f"classes.{name}: unknown check {check_id!r} "
                        f"(known checks: {known})"
                    )
            message = _CLASS_MESSAGES.get(
                (class_def.code, bool(class_def.checks))
            )
            if message is not None:
                self.violations.append(message.format(name=name))

    def _check_rules(self) -> None:
        known = _known_names(sorted(self.config.classes))
        for rule, (invalid, message) in product(
            self.config.rules, _RULE_CHECKS
        ):
            if invalid(rule, self.config):
                self.violations.append(
                    message.format(
                        index=rule.index,
                        pattern=repr(rule.pattern),
                        class_name=repr(rule.class_name),
                        known_classes=known,
                    )
                )

    def _classify_files(self) -> None:
        for entry in self.entries:
            relative = entry.path
            hits = []
            for index, rule in enumerate(self.config.rules):
                if fnmatch.fnmatchcase(relative, rule.pattern):
                    hits.append((index, rule))
                    self.matched[index] += 1
            patterns = ", ".join(
                repr(rule.pattern) for _index, rule in hits
            )
            message = _FILE_HIT_MESSAGES[min(len(hits), 2)]
            if message is not None:
                self.violations.append(
                    message.format(
                        relative=relative,
                        count=len(hits),
                        patterns=patterns,
                    )
                )
                continue
            self._classify(entry, hits[0][1])

    def _classify(self, entry: GitFile, rule: Rule) -> None:
        relative = entry.path
        class_def = self.config.classes.get(rule.class_name)
        if class_def is None:
            return
        self.classes[relative] = rule.class_name
        if relative in self.gitlinks:
            return
        source = self._record_source(relative)
        if source is None:
            return
        message = _FILE_CLASS_MESSAGES.get((source.code, class_def.code))
        if message is not None:
            self.violations.append(
                message.format(
                    relative=relative,
                    class_name=repr(rule.class_name),
                    pattern=repr(rule.pattern),
                )
            )

    def _record_source(self, relative: str) -> SourceClassification | None:
        try:
            source = source_language(self.root / relative, relative, self.config, selected=False)
        except OSError as error:
            self.violations.append(f"{relative}: cannot read shebang: {error}")
            return None
        self.sources[relative] = source
        return source

    def _check_module_placement(self, paths: set[str], modules: tuple[str, ...]) -> list[str]:
        declared = _known_names(map(repr, modules))
        outside = _outside_module_paths(paths, modules)
        for relative in outside:
            if relative not in self.classes:
                self._record_source(relative)
            source = self.sources.get(relative)
            if source is not None and source.code:
                self.violations.append(
                    f"{relative}: code file outside declared module directories ({declared})"
                )
        return outside


def _outside_module_paths(paths: set[str], modules: tuple[str, ...]) -> list[str]:
    prefixes = tuple(f"{module}/" for module in modules)
    return [path for path in sorted(paths) if not path.startswith(prefixes)]


def _tracked_paths(entries: list[GitFile]) -> set[str]:
    return {entry.path for entry in entries if entry.mode is not None}


def _unused_rule_violations(rules: tuple[Rule, ...], matched: list[int]) -> list[str]:
    return [
        f"rule[{rule.index}] (pattern {rule.pattern!r}): matches no file"
        for rule, hits in zip(rules, matched, strict=True)
        if hits == 0
    ]


def _unused_module_violations(
    entries: list[GitFile], gitlinks: set[str], modules: tuple[str, ...]
) -> list[str]:
    tracked = _tracked_paths(entries) - gitlinks
    return [
        f"module_dirs: unused module directory {module!r} (contains no tracked file)"
        for module in modules
        if not any(path.startswith(f"{module}/") for path in tracked)
    ]


def validate_inventory(
    root: Path, config: Config
) -> tuple[list[str], dict[str, str], list[str]]:
    entries, violations = _reject_special_files(
        root, enumerate_entries(root)
    )
    return _InventoryValidator(
        root,
        config,
        entries,
        violations,
        [0] * len(config.rules),
        {},
        {entry.path for entry in entries if entry.gitlink},
    ).validate()


@dataclass(frozen=True)
class _InventoryOutcome:
    status: int
    stream: str
    templates: tuple[str, ...]
    lines_key: str = ""


_INVENTORY_OUTCOMES = {
    "unknown_class": _InventoryOutcome(
        2,
        "stderr",
        (
            "inventory: unknown class {value}; "
            "known classes: {known}",
        ),
    ),
    "error": _InventoryOutcome(
        1, "stderr", ("inventory: {value}",)
    ),
    "violations": _InventoryOutcome(
        1, "stderr", (), "violations_lines"
    ),
    "listing": _InventoryOutcome(0, "stdout", (), "listing_lines"),
    "summary": _InventoryOutcome(
        0,
        "stdout",
        ("inventory: {files} files match {rules} rules",),
    ),
}


def _inventory_lines(
    kind: str, values: dict[str, object]
) -> tuple[int, str, tuple[str, ...]]:
    outcome = _INVENTORY_OUTCOMES[kind]
    lines = values.get(outcome.lines_key)
    if not lines:
        lines = tuple(
            template.format(**values) for template in outcome.templates
        )
    return outcome.status, outcome.stream, tuple(lines)


def _inventory_kind(
    unknown: bool, violations: list[str], listing: bool
) -> str:
    if unknown:
        return "unknown_class"
    if violations:
        return "violations"
    if listing:
        return "listing"
    return "summary"


def _inventory_outcome(
    files: list[str],
    classes: dict[str, str],
    violations: list[str],
    config: Config,
    list_class: str | None,
) -> tuple[int, str, tuple[str, ...]]:
    unknown = list_class not in (None, *config.classes)
    violations_lines = [
        f"inventory: {violation}" for violation in violations
    ]
    listing_lines = [
        relative
        for relative in sorted(classes)
        if classes[relative] == list_class
    ]
    kind = _inventory_kind(
        unknown, violations, list_class is not None
    )
    return _inventory_lines(
        kind,
        {
            "files": len(files),
            "rules": len(config.rules),
            "value": repr(list_class),
            "known": _known_names(sorted(config.classes)),
            "violations_lines": violations_lines,
            "listing_lines": listing_lines,
        },
    )


def command_inventory(
    root: Path, config: Config, list_class: str | None = None
) -> int:
    if list_class is not None and list_class not in config.classes:
        status, stream, lines = _inventory_outcome(
            [], {}, [], config, list_class
        )
    else:
        try:
            files, classes, violations = validate_inventory(root, config)
        except GateError as error:
            status, stream, lines = _inventory_lines(
                "error", {"value": error}
            )
        else:
            status, stream, lines = _inventory_outcome(
                files, classes, violations, config, list_class
            )
    for line in lines:
        print(line, file=getattr(sys, stream))
    return status


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
            info = (root / relative).lstat()
        except OSError as error:
            violations.append(
                f"hygiene: {relative}: cannot measure size: {error}"
            )
            continue
        kind = _type_name(info.st_mode)
        if kind is not None:
            violations.append(
                f"hygiene: {relative}: unsupported file type {kind} "
                "(expected a regular file or symlink)"
            )
            continue
        if info.st_size > max_bytes:
            violations.append(
                f"hygiene: {relative}: {info.st_size} bytes exceeds max_bytes "
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
