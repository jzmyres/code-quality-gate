"""Inventory environment accesses in Python and Emacs Lisp source."""
from __future__ import annotations

import ast
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .elisp_lint import batch_command
from .elisp_tests import _lisp_string, _temporary
from .json_input import load_json
from .policy import GateError, _check_keys, _config_error, _describe, _string
from .runner import run
from .verification import _is_python_program

if TYPE_CHECKING:
    from .adapters import AdapterContext, ParsedSpec


@dataclass(frozen=True)
class AllowEntry:
    owner: str
    name: str | None = None
    prefix: str | None = None

    def matches(self, name: str) -> bool:
        if self.prefix is not None:
            return name.startswith(self.prefix)
        return name == self.name


@dataclass(frozen=True)
class Finding:
    name: str | None
    path: str
    line: int
    access: str

    def allowed(self, entries: tuple[AllowEntry, ...]) -> bool:
        return self.name is not None and any(entry.matches(self.name) for entry in entries)


def _allow_entry(raw: Any, path: Path, key: str) -> AllowEntry:
    if not isinstance(raw, dict):
        raise _config_error(path, key, "an allowlist table", _describe(raw))
    _check_keys(raw, ("name", "prefix", "owner"), path, key)
    selectors = raw.keys() & {"name", "prefix"}
    if len(selectors) != 1:
        raise _config_error(path, key, "exactly one of name or prefix", repr(raw))
    selector, = selectors
    return AllowEntry(
        _string(raw, "owner", path, f"{key}.owner"),
        **{selector: _string(raw, selector, path, f"{key}.{selector}")},
    )


def parse_spec(raw: dict[str, Any], _root: Path, path: Path, key: str) -> ParsedSpec:
    """Parse an allowlist, defaulting to no allowed names."""
    from .adapters import ParsedSpec

    entries = raw.get("allow", [])
    if not isinstance(entries, list):
        raise _config_error(path, f"{key}.allow", "an array of tables", _describe(entries))
    allowed = tuple(
        _allow_entry(entry, path, f"{key}.allow[{index}]")
        for index, entry in enumerate(entries)
    )
    return ParsedSpec(allowed, "env-surface/1", ("static",))


class PythonImports(ast.NodeVisitor):
    """Collect import bindings in a lexical scope."""

    def __init__(self, body: list[ast.stmt]) -> None:
        self.names: dict[str, str] = {}
        for statement in body:
            self.visit(statement)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module = alias.name.split(".")[0]
            self.names[alias.asname or module] = alias.name if alias.asname else module

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.names[alias.asname or alias.name] = f"{'.' * node.level}{node.module}.{alias.name}"

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        """Leave nested imports to their own scope."""
        return None

    visit_AsyncFunctionDef = visit_ClassDef = visit_FunctionDef


def _argument(call: ast.Call, position: int, keyword: str) -> ast.expr | None:
    for arg in call.keywords:
        if arg.arg == keyword:
            return arg.value
    if position < len(call.args) and not any(
        isinstance(arg, ast.Starred) for arg in call.args[:position + 1]
    ):
        return call.args[position]
    return None


# The environment argument has a fixed position in these os APIs.
_OS_ENV_ARGUMENTS = {
    "execle": 2, "execlpe": 2,
    "execve": 2, "execvpe": 2,
    "spawnle": 3, "spawnlpe": 3,
    "spawnve": 3, "spawnvpe": 3,
    "posix_spawn": 2, "posix_spawnp": 2,
}


def _os_process_environment(call: ast.Call, target: str) -> ast.expr | None:
    module, _, function = target.rpartition(".")
    if module != "os" or function not in _OS_ENV_ARGUMENTS:
        return None
    position = _OS_ENV_ARGUMENTS[function]
    if function.startswith(("execl", "spawnl")):
        position = max(position, len(call.args) - 1)
    return _argument(call, position, "env")


def _process_environment(call: ast.Call, target: str) -> ast.expr | None:
    if target.startswith("subprocess."):
        return next((arg.value for arg in call.keywords if arg.arg == "env"), None)
    return _os_process_environment(call, target)


_KEYED_METHODS = {
    "get": "read", "__getitem__": "read",
    "pop": "write", "setdefault": "write", "__setitem__": "write", "__delitem__": "write",
}


class PythonReader(ast.NodeVisitor):
    """Resolve imported names and inventory environment operations in the AST."""

    def __init__(self, tree: ast.Module, path: str) -> None:
        self.names = PythonImports(tree.body).names
        self.path = path
        self.findings: list[Finding] = []
        self.consumed: set[ast.AST] = set()

    def visit_body(self, body: list[ast.stmt], names: dict[str, str]) -> None:
        previous = self.names
        self.names = names | PythonImports(body).names
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.names = previous

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        body = set(node.body)
        for child in ast.iter_child_nodes(node):
            if child not in body:
                self.visit(child)
        arguments = node.args
        parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                      arguments.vararg, arguments.kwarg]
        shadowed = {arg.arg: "" for arg in parameters if arg is not None}
        self.visit_body(node.body, self.names | shadowed)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.bases, *node.keywords, *node.decorator_list]:
            self.visit(expression)
        self.visit_body(node.body, self.names)

    def qualified(self, node: ast.AST | None) -> str:
        if isinstance(node, ast.Name):
            return self.names.get(node.id, "")
        if isinstance(node, ast.Attribute):
            return f"{self.qualified(node.value)}.{node.attr}"
        return ""

    def environ(self, node: ast.AST | None) -> bool:
        return self.qualified(node) in ("os.environ", "os.environb")

    def record(self, node: ast.AST, key: ast.AST | str | None, access: str) -> None:
        value = key.value if isinstance(key, ast.Constant) else key
        name = value if isinstance(value, str) else None
        kind = access if name is not None else "computed"
        self.findings.append(Finding(name, self.path, node.lineno, kind))

    def visit(self, node: ast.AST) -> Any:
        if node not in self.consumed and self.environ(node):
            self.record(node, None, "read")
        return super().visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.environ(node.value):
            self.consumed.add(node.value)
            self.record(node, node.slice, "read" if isinstance(node.ctx, ast.Load) else "write")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        for left, op, right in zip(operands[:-1], node.ops, node.comparators, strict=True):
            if isinstance(op, (ast.In, ast.NotIn)) and self.environ(right):
                self.consumed.add(right)
                self.record(node, left, "read")
        self.generic_visit(node)

    def inherited(self, value: ast.expr) -> bool:
        if self.environ(value):
            self.consumed.add(value)
            return True
        if self.is_copy(value):
            self.consumed.add(value.func.value)
            return True
        return False

    def dict_writes(self, value: ast.Dict, *, inherited: bool) -> None:
        for key, item in zip(value.keys, value.values, strict=True):
            if inherited and key is None and self.environ(item):
                self.consumed.add(item)
            else:
                self.record(key or item, key, "write")

    def pair_writes(self, value: ast.List | ast.Tuple) -> None:
        for pair in value.elts:
            if isinstance(pair, (ast.List, ast.Tuple)) and len(pair.elts) == 2:
                self.record(pair.elts[0], pair.elts[0], "write")
            else:
                self.record(pair, None, "write")

    def mapping(self, call: ast.Call, value: ast.expr, *, inherited: bool) -> None:
        if inherited and self.inherited(value):
            return
        if isinstance(value, ast.Dict):
            self.dict_writes(value, inherited=inherited)
        elif not inherited and isinstance(value, (ast.List, ast.Tuple)):
            self.pair_writes(value)
        else:
            self.record(call, None, "write")

    def is_copy(self, node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "copy" and self.environ(node.func.value)
            and not node.args and not node.keywords
        )

    def update(self, node: ast.Call) -> None:
        for value in node.args:
            self.mapping(node, value, inherited=False)
        for arg in node.keywords:
            self.record(arg, arg.arg, "write")

    def environment_method(self, node: ast.Call, method: ast.Attribute) -> None:
        if method.value in self.consumed:
            return
        self.consumed.add(method.value)
        if method.attr == "update":
            self.update(node)
        else:
            access = _KEYED_METHODS.get(method.attr)
            key = _argument(node, 0, "key") if access else None
            self.record(node, key, access or "read")

    def visit_Call(self, node: ast.Call) -> None:
        target = self.qualified(node.func)
        if target in ("os.getenv", "os.getenvb", "os.putenv", "os.unsetenv"):
            access = "read" if target.startswith("os.getenv") else "write"
            self.record(node, _argument(node, 0, "key"), access)
        elif isinstance(node.func, ast.Attribute) and self.environ(node.func.value):
            self.environment_method(node, node.func)
        else:
            environment = _process_environment(node, target)
            if environment is not None:
                self.mapping(node, environment, inherited=True)
        self.generic_visit(node)


def _python_findings(root: Path, path: str) -> list[Finding]:
    try:
        tree = ast.parse((root / path).read_bytes(), filename=path)
    except (OSError, SyntaxError, ValueError) as error:
        raise GateError(f"cannot read {path}: {error}") from error
    reader = PythonReader(tree, path)
    reader.visit(tree)
    return reader.findings


def _elisp_findings(root: Path, files: list[str], budget: int) -> tuple[list[Finding], list[str]]:
    helper = Path(__file__).with_name("elisp") / "qg-env-surface.el"
    names = " ".join(map(_lisp_string, files))
    try:
        with _temporary() as temporary:
            report = Path(temporary) / "result.json"
            form = f"(qg-env-surface-run '({names}) {_lisp_string(str(report))})"
            child = run(batch_command("emacs", helper, form), cwd=root, budget_seconds=budget)
            if child.returncode != 0:
                raise ValueError(child.error or child.combined_text.strip())
            document = load_json(report.read_text(encoding="utf-8"))
        return [Finding(**row) for row in document["findings"]], document["errors"]
    except (OSError, TypeError, ValueError, KeyError) as error:
        return [], [f"cannot read Emacs Lisp files {', '.join(files)}: {error}"]


def measure(root: Path, files: list[str], budget: int = 30) -> tuple[list[Finding], list[str]]:
    """Read each selected file and return inventory rows and driver errors."""
    findings, errors, elisp = [], [], []
    for path in sorted(set(files)):
        try:
            if path.endswith(".el"):
                elisp.append(path)
            elif _is_python_program(root, path):
                findings.extend(_python_findings(root, path))
            else:
                errors.append(f"{path}: no env_surface driver")
        except GateError as error:
            errors.append(str(error))
    if elisp:
        rows, failures = _elisp_findings(root, elisp, budget)
        findings.extend(rows)
        errors.extend(failures)
    return sorted(findings, key=lambda row: (row.path, row.line)), errors


def _problems(findings: list[Finding], allow: tuple[AllowEntry, ...]) -> list[str]:
    return [
        f"{row.path}:{row.line}: {row.access} {row.name!r}"
        for row in findings if not row.allowed(allow)
    ]


def _failure_reason(errors: list[str], violations: int) -> str | None:
    messages = list(errors)
    if violations:
        messages.append(f"{violations} environment accesses are outside the allowlist or computed")
    return "\n".join(messages) or None


def run_check(context: AdapterContext) -> Any:
    """Report the complete inventory and fail on unapproved access or unread files."""
    from .checks import _adapter_selection, _check_result

    allow, start, selected, _classes = _adapter_selection(context)
    findings, errors = measure(context.root, selected)
    violations = _problems(findings, allow)
    for problem in [*errors, *violations]:
        print(f"{context.prefix}: {problem}", file=sys.stderr)
    reason = _failure_reason(errors, len(violations))
    return _check_result(
        context.check, start, "fail" if reason else "pass", reason=reason,
        measurement={"findings": [asdict(row) for row in findings]},
    )
