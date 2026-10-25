"""The command-line interface, check orchestration and main."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import command_check
from .clones import command_clones
from .files import command_hygiene, command_inventory, resolve_repo
from .gate_result import error_document
from .policy import UsageError, load_config
from .tools import _default_lock_path, command_tools_fetch, command_tools_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qg.py",
        description="Tiered policy checks, inventory, hygiene and pinned tools.",
    )
    parser.add_argument(
        "--repo",
        metavar="DIR",
        help="top level of the git work tree (default: current directory)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser("inventory", help="classify every file")
    inventory.add_argument(
        "--list", dest="list_class", metavar="CLASS", help="print one class's files"
    )
    commands.add_parser("hygiene", help="check ignored and oversized files")
    clones = commands.add_parser("clones", help="check the duplicate-code ratchet")
    clones.add_argument(
        "--prune", action="store_true", help="remove resolved baseline entries"
    )
    tools = commands.add_parser("tools", help="manage pinned external tools")
    tool_commands = tools.add_subparsers(dest="tools_command", required=True)
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
        metavar="ID",
        help="lower one check's baseline after it passes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "tools":
        lock = (
            Path(args.lock).expanduser()
            if getattr(args, "lock", None)
            else _default_lock_path()
        )
        if args.tools_command == "fetch":
            return command_tools_fetch(lock)
        return command_tools_path(lock, args.name)

    root: Path | None = None
    try:
        root = resolve_repo(args.repo)
        config = load_config(root)
    except UsageError as error:
        print(error, file=sys.stderr)
        if args.command == "check" and args.json:
            guessed = root
            if guessed is None and args.repo is not None:
                guessed = Path(args.repo).expanduser()
            policy = guessed / "quality-gate.toml" if guessed is not None else None
            print(
                json.dumps(error_document(guessed, policy, str(error)), indent=2),
                file=sys.stdout,
            )
        return error.exit_code

    if args.command == "inventory":
        return command_inventory(root, config, args.list_class)
    if args.command == "hygiene":
        return command_hygiene(root, config)
    if args.command == "clones":
        return command_clones(root, config, args.prune)
    return command_check(
        root,
        config,
        json_output=args.json,
        prune_id=args.prune,
    )
