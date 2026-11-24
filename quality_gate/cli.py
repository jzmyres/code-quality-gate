"""The command-line interface, check orchestration and main."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import checks
from .adapters import ADAPTERS
from .files import (
    BUILTIN_RESULT_KINDS,
    command_hygiene,
    command_inventory,
    resolve_repo,
)
from .gate_result import error_document
from .policy import CheckDef, Config, UsageError, load_config
from .tools import (
    _default_lock_path,
    command_tools_fetch,
    command_tools_path,
    load_tools,
)
from .trust import prepare_trust
from .worklist import command_debt, command_worklist

AGENT_SANDBOX_ENV = "QG_AGENT"
AGENT_REFUSAL = (
    "qg.py: check: refused inside an agent sandbox (QG_AGENT=1): "
    "selected checks run a test suite: {refused}. "
    "the runner's gate runs the test suites once per candidate and returns "
    "its log; run focused tests directly, or a static check with --only NAME; "
    "allowed here: {allowed}"
)


def _agent_allowed_check_names(config: Config) -> str:
    """The policy's check ids whose adapters do not run a suite."""
    return ", ".join(
        check.id for check in config.checks.values()
        if not ADAPTERS[check.adapter].runs_suite
    )


def _agent_selected_checks(
    config: Config, only_ids: list[str] | None
) -> list[CheckDef]:
    """The checks `check` selects, exactly as the check command selects them."""
    if only_ids is None:
        return list(config.checks.values())
    identifiers = checks._selected_check_ids(config, only_ids)
    assert identifiers is not None
    return [config.checks[identifier] for identifier in identifiers]


def _agent_refusal(config: Config, selected: list[CheckDef]) -> str | None:
    """The refusal message when a selected check runs a whole test suite."""
    refused = [
        check for check in selected
        if ADAPTERS[check.adapter].runs_suite
    ]
    if not refused:
        return None
    return AGENT_REFUSAL.format(
        refused=", ".join(f"{check.id} ({check.adapter})" for check in refused),
        allowed=_agent_allowed_check_names(config) or "none",
    )


def _refuse_in_agent_sandbox(config: Config, only_ids: list[str] | None) -> None:
    """Refuse a suite-running check inside an agent sandbox, before it runs."""
    if os.environ.get(AGENT_SANDBOX_ENV) != "1":
        return
    message = _agent_refusal(config, _agent_selected_checks(config, only_ids))
    if message is not None:
        raise UsageError(message)


class _Parser(argparse.ArgumentParser):
    """An argument parser whose errors are UsageError, not SystemExit."""

    def error(self, message: str) -> None:
        raise UsageError(f"{self.prog}: {message}")


def _add_policy_from_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-from",
        metavar="DIR",
        help="evaluate the working tree against an absolute trusted "
        "directory's policy and inputs",
    )


def _add_allow_protected_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-protected",
        metavar="PATH",
        action="append",
        default=[],
        help="authorize the candidate's version of a protected path",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="qg.py",
        description="Tiered policy checks, inventory, hygiene and pinned tools.",
    )
    parser.add_argument(
        "--repo",
        metavar="DIR",
        help="top level of the git work tree (default: current directory)",
    )
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_Parser
    )

    inventory = commands.add_parser("inventory", help="classify every file")
    inventory.add_argument(
        "--list", dest="list_class", metavar="CLASS", help="print one class's files"
    )
    _add_policy_from_argument(inventory)
    _add_allow_protected_argument(inventory)
    commands.add_parser("hygiene", help="check ignored and oversized files")
    tools = commands.add_parser("tools", help="manage pinned external tools")
    tool_commands = tools.add_subparsers(
        dest="tools_command", required=True, parser_class=_Parser
    )
    fetch = tool_commands.add_parser("fetch", help="install or verify pinned tools")
    fetch.add_argument("--lock", metavar="FILE", help="tool lock file")
    fetch.add_argument(
        "--check", action="store_true", help="verify existing installs offline and read-only"
    )
    path = tool_commands.add_parser("path", help="print a pinned tool's binary")
    path.add_argument("name", metavar="NAME")
    check = commands.add_parser("check", help="run every configured check")
    check.add_argument(
        "--json",
        action="store_true",
        help="write one JSON result document to stdout",
    )
    check.add_argument(
        "--only",
        metavar="CHECK",
        nargs="+",
        help="run only these checks and their prerequisites as a partial run",
    )
    check.add_argument(
        "--prune",
        metavar="ID|all",
        action="append",
        default=[],
        help="tighten a check's baseline after it passes (repeatable; all selects every baseline)",
    )
    _add_policy_from_argument(check)
    _add_allow_protected_argument(check)
    worklist = commands.add_parser(
        "worklist", help="rank baseline debt by churn x current value"
    )
    worklist.add_argument(
        "--json",
        action="store_true",
        help="write one JSON worklist document to stdout",
    )
    worklist.add_argument(
        "check_ids",
        metavar="CHECK",
        nargs="*",
        help="check id (default: every check with a baseline)",
    )
    debt = commands.add_parser(
        "debt", help="list baseline debt without running any check"
    )
    debt.add_argument(
        "--revision",
        metavar="REV",
        help="read the policy and baselines at this commit",
    )
    debt.add_argument(
        "--json",
        action="store_true",
        help="write one JSON debt document to stdout",
    )
    return parser


def _repo_hint(raw: list[str]) -> Path | None:
    for index, argument in enumerate(raw):
        if argument == "--repo" and index + 1 < len(raw):
            return Path(raw[index + 1]).expanduser()
        if argument.startswith("--repo="):
            return Path(argument.split("=", 1)[1]).expanduser()
    return None


def _print_error_document(
    root: Path | None,
    message: str,
    *,
    prune: dict[str, Any] | None = None,
) -> None:
    policy = root / "quality-gate.toml" if root is not None else None
    print(
        json.dumps(
            error_document(root, policy, message, prune=prune),
            indent=2,
            allow_nan=False,
        ),
        file=sys.stdout,
    )


def _reject_nul(raw: list[str]) -> None:
    if any("\x00" in argument for argument in raw):
        raise UsageError(
            "qg.py: command line: expected an argument without NUL, "
            "got embedded NUL"
        )


def _run_builtin(root: Path, config: Any, args: Any) -> int:
    if args.command == "inventory":
        return command_inventory(root, config, args.list_class)
    return command_hygiene(root, config)


def _dispatch(root: Path, config: Any, args: Any) -> int:
    _reject_partial_options(args)
    if args.command in BUILTIN_RESULT_KINDS:
        return _run_builtin(root, config, args)
    if args.command == "worklist":
        return command_worklist(root, config, args.check_ids, args.json)
    _refuse_in_agent_sandbox(config, args.only)
    return checks.command_check(
        root,
        config,
        json_output=args.json,
        prune_ids=args.prune,
        only_ids=args.only,
    )


def _run_tools(args: Any) -> int:
    lock = (
        Path(args.lock).expanduser()
        if getattr(args, "lock", None)
        else _default_lock_path()
    )
    if args.tools_command == "fetch":
        return command_tools_fetch(lock, check=args.check)
    return command_tools_path(lock, args.name)


def _run_trusted_check(root: Path, args: Any) -> int:
    _reject_partial_options(args)
    if args.prune:
        raise UsageError(
            "qg.py: --prune: cannot be combined with --policy-from"
        )
    trust = prepare_trust(root, args.policy_from, args.allow_protected)
    try:
        _refuse_in_agent_sandbox(trust.config, args.only)
    except UsageError:
        trust.close()
        raise
    return checks.command_check(
        root,
        trust.config,
        json_output=args.json,
        prune_ids=args.prune,
        only_ids=args.only,
        trust=trust,
    )


def _run_trusted_inventory(root: Path, args: Any) -> int:
    trust = prepare_trust(root, args.policy_from, args.allow_protected)
    try:
        if trust.report_blocked():
            return 1
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = command_inventory(root, trust.config, args.list_class)
        code, _ = trust.finish(code, {})
        if code == 0:
            print(stream.getvalue(), end="")
        return code
    finally:
        trust.close()


_TRUSTED_COMMANDS = {
    "check": _run_trusted_check,
    "inventory": _run_trusted_inventory,
}


def _reject_partial_options(args: Any) -> None:
    if not getattr(args, "only", None):
        return
    if args.prune:
        raise UsageError("qg.py: --only: cannot be combined with --prune")
    if args.policy_from is not None:
        raise UsageError("qg.py: --only: cannot be combined with --policy-from")


def _run_gate(root: Path, args: Any) -> int:
    trusted = _TRUSTED_COMMANDS.get(args.command)
    if trusted is not None and args.policy_from is not None:
        return trusted(root, args)
    if getattr(args, "allow_protected", None):
        raise UsageError(
            "qg.py: --allow-protected: expected --policy-from"
        )
    if args.command == "debt":
        return command_debt(root, args.revision, args.json)
    config = load_config(root)
    load_tools(_default_lock_path())
    return _dispatch(root, config, args)


def _main(raw: list[str]) -> int:
    json_requested = "--json" in raw
    root: Path | None = None
    try:
        _reject_nul(raw)
        args = build_parser().parse_args(raw)
        if args.command == "tools":
            return _run_tools(args)
        root = resolve_repo(args.repo)
        return _run_gate(root, args)
    except UsageError as error:
        print(error, file=sys.stderr)
        if json_requested:
            if root is None:
                root = _repo_hint(raw)
            _print_error_document(root, str(error))
        return error.exit_code


def main(argv: list[str] | None = None) -> int:
    return _main(list(sys.argv[1:] if argv is None else argv))
