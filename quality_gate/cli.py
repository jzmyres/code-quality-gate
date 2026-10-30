"""The command-line interface, check orchestration and main."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any

from .checks import command_check
from .files import command_hygiene, command_inventory, resolve_repo
from .gate_result import error_document
from .policy import UsageError, load_config
from .tools import (
    _default_lock_path,
    command_tools_fetch,
    command_tools_path,
    load_tools,
)
from .trust import prepare_trust
from .worklist import command_worklist


class _Parser(argparse.ArgumentParser):
    """An argument parser whose errors are UsageError, not SystemExit."""

    def error(self, message: str) -> None:
        raise UsageError(f"{self.prog}: {message}")


def _add_policy_from_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-from",
        metavar="REV",
        help="evaluate the working tree against REV's policy and inputs",
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
    fetch = tool_commands.add_parser("fetch", help="download and verify pinned tools")
    fetch.add_argument("--lock", metavar="FILE", help="tool lock file")
    path = tool_commands.add_parser("path", help="print a pinned tool's binary")
    path.add_argument("name", metavar="NAME")
    check = commands.add_parser("check", help="run every configured check")
    check.add_argument(
        "--json",
        action="store_true",
        help="write one JSON result document to stdout",
    )
    check.add_argument(
        "--prune",
        metavar="ID|all",
        action="append",
        default=[],
        help="tighten a check's baseline after it passes (repeatable; all selects every baseline)",
    )
    _add_policy_from_argument(check)
    check.add_argument(
        "--changed-from",
        metavar="REV",
        help="also reject threshold violations on lines changed since REV",
    )
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


def _dispatch(root: Path, config: Any, args: Any) -> int:
    if args.command == "inventory":
        return command_inventory(root, config, args.list_class)
    if args.command == "hygiene":
        return command_hygiene(root, config)
    if args.command == "worklist":
        return command_worklist(root, config, args.check_ids, args.json)
    return command_check(
        root,
        config,
        json_output=args.json,
        prune_ids=args.prune,
        changed_from=args.changed_from,
    )


def _run_tools(args: Any) -> int:
    lock = (
        Path(args.lock).expanduser()
        if getattr(args, "lock", None)
        else _default_lock_path()
    )
    if args.tools_command == "fetch":
        return command_tools_fetch(lock)
    return command_tools_path(lock, args.name)


def _run_trusted_check(root: Path, args: Any) -> int:
    trust = prepare_trust(root, args.policy_from, args.allow_protected)
    return command_check(
        root,
        trust.config,
        json_output=args.json,
        prune_ids=args.prune,
        trust=trust,
        changed_from=args.changed_from,
    )


def _run_trusted_inventory(root: Path, args: Any) -> int:
    trust = prepare_trust(root, args.policy_from, args.allow_protected)
    try:
        if trust.report_blocked():
            return 1
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = command_inventory(root, trust.config, args.list_class)
        code, _ = trust.finish(code, {}, report_gitlinks=False)
        if code == 0:
            print(stream.getvalue(), end="")
        return code
    finally:
        trust.close()


def _run_gate(root: Path, args: Any) -> int:
    if args.command in ("check", "inventory") and args.policy_from is not None:
        if args.command == "check":
            return _run_trusted_check(root, args)
        return _run_trusted_inventory(root, args)
    if getattr(args, "allow_protected", None):
        raise UsageError(
            "qg.py: --allow-protected: expected --policy-from"
        )
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
