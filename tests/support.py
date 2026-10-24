"""Shared helpers for the quality-gate tests."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

GATE = Path(__file__).resolve().parent.parent
QG = GATE / "qg.py"
JSCPD_VERSION = "5.4.1"

BASE_CONFIG = """\
[code]
patterns = ["*.py", "*.sh", "*.el"]
shebangs = ["sh", "bash", "python*"]

[classes.python]
code = true
description = "Python source"

[classes.doc]
code = false
description = "Documentation"

[classes.config]
code = false
description = "Configuration"

[[rule]]
pattern = "*.py"
class = "python"
reason = "Python source"

[[rule]]
pattern = "*.md"
class = "doc"
reason = "Documentation"

[[rule]]
pattern = "*.toml"
class = "config"
reason = "Configuration"

[[rule]]
pattern = ".gitignore"
class = "config"
reason = "Ignore rules"
"""

BASE_FILES = {
    "a.py": "print('a')\n",
    "README.md": "# fixture\n",
    ".gitignore": "__pycache__/\n",
}

FAKE_JSCPD = """\
#!@PYTHON@
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if "--fail-on-empty" not in args:
    print("fake jscpd: --fail-on-empty missing", file=sys.stderr)
    sys.exit(9)
args_file = os.environ.get("QG_FAKE_ARGS")
if args_file:
    pathlib.Path(args_file).write_text("\\n".join(args), encoding="utf-8")
exit_code = int(os.environ.get("QG_FAKE_EXIT", "0"))
if exit_code:
    print(os.environ.get("QG_FAKE_ERROR", "fake jscpd failed"), file=sys.stderr)
    sys.exit(exit_code)
if os.environ.get("QG_FAKE_NO_REPORT") == "1":
    sys.exit(0)
output = pathlib.Path(args[args.index("--output") + 1])
output.mkdir(parents=True, exist_ok=True)
sarif = json.loads(
    pathlib.Path(os.environ["QG_FAKE_SARIF"]).read_text(encoding="utf-8")
)
(output / "jscpd-report.sarif").write_text(
    json.dumps(sarif), encoding="utf-8"
)
"""


def with_clones(
    classes: str = '["python"]',
    min_tokens: int = 50,
    baseline: str = "quality-gate-clones.toml",
) -> str:
    return (
        BASE_CONFIG
        + "\n[clones]\n"
        + f"classes = {classes}\n"
        + f"min_tokens = {min_tokens}\n"
        + f'baseline = "{baseline}"\n'
    )


def baseline_text(entries: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for entry in entries:
        lines.append("[[clone]]")
        lines.append(f'fingerprint = "{entry["fingerprint"]}"')
        if "count" in entry:
            lines.append(f'count = {entry["count"]}')
        if "files" in entry:
            files = ", ".join(f'"{item}"' for item in entry["files"])
            lines.append(f"files = [{files}]")
        lines.append(f'reason = "{entry.get("reason", "")}"')
        lines.append("")
    return "\n".join(lines)


def sarif_report(clones: list[tuple[str, list[tuple[str, int, int]]]]) -> dict[str, Any]:
    results = []
    for fingerprint, locations in clones:
        first = locations[0]
        result: dict[str, Any] = {
            "partialFingerprints": {"jscpdCloneHash/v1": fingerprint},
            "locations": [sarif_location(first)],
        }
        if len(locations) > 1:
            result["relatedLocations"] = [
                sarif_location(location) for location in locations[1:]
            ]
        results.append(result)
    return {"version": "2.1.0", "runs": [{"results": results}]}


def sarif_location(location: tuple[str, int, int]) -> dict[str, Any]:
    uri, start, end = location
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": start, "endLine": end},
        }
    }


class FixtureCase(unittest.TestCase):
    """A disposable git repository, a disposable HOME, and qg.py subprocesses."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="qg-test-")
        self.addCleanup(self._temporary.cleanup)
        self.base = Path(self._temporary.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        for name, content in BASE_FILES.items():
            self.add_file(name, content)
        self.write_config()

    @property
    def config_path(self) -> Path:
        return self.repo / "quality-gate.toml"

    def add_file(self, relative: str, content: str | bytes) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def read_file(self, relative: str) -> str:
        return (self.repo / relative).read_text(encoding="utf-8")

    def write_config(self, text: str | None = None) -> None:
        self.config_path.write_text(
            BASE_CONFIG if text is None else text, encoding="utf-8"
        )

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )

    def env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        for key in (
            "QG_TOOLS_DIR",
            "QG_FAKE_SARIF",
            "QG_FAKE_EXIT",
            "QG_FAKE_ERROR",
            "QG_FAKE_ARGS",
            "QG_FAKE_NO_REPORT",
        ):
            env.pop(key, None)
        env.update(
            {
                "HOME": str(self.home),
                "XDG_CONFIG_HOME": str(self.home / ".config"),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "qg test",
                "GIT_AUTHOR_EMAIL": "qg@example.invalid",
                "GIT_COMMITTER_NAME": "qg test",
                "GIT_COMMITTER_EMAIL": "qg@example.invalid",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        if extra:
            env.update(extra)
        return env

    def run_qg(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        repo: Path | None = None,
        include_repo: bool = True,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-I", str(QG)]
        if include_repo:
            command.extend(["--repo", str(repo or self.repo)])
        command.extend(args)
        return subprocess.run(
            command,
            cwd=str(cwd or self.repo),
            env=self.env(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def install_fake_jscpd(
        self,
        sarif: dict[str, Any] | None = None,
        *,
        exit_code: int = 0,
        report: bool = True,
        error: str = "",
        args_file: Path | None = None,
    ) -> dict[str, str]:
        tools = self.base / "tools"
        destination = tools / f"jscpd-{JSCPD_VERSION}"
        destination.mkdir(parents=True, exist_ok=True)
        binary = destination / "jscpd"
        binary.write_text(
            FAKE_JSCPD.replace("@PYTHON@", sys.executable), encoding="utf-8"
        )
        binary.chmod(0o755)
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text(
            json.dumps(sarif if sarif is not None else sarif_report([])),
            encoding="utf-8",
        )
        env = {
            "QG_TOOLS_DIR": str(tools),
            "QG_FAKE_SARIF": str(sarif_path),
        }
        if exit_code:
            env["QG_FAKE_EXIT"] = str(exit_code)
        if not report:
            env["QG_FAKE_NO_REPORT"] = "1"
        if error:
            env["QG_FAKE_ERROR"] = error
        if args_file is not None:
            env["QG_FAKE_ARGS"] = str(args_file)
        return env

    def default_tool_env(self) -> dict[str, str]:
        """Environment for the test of the real, already installed jscpd.

        The tools directory resolves as qg.py resolves it: the caller's QG_TOOLS_DIR when set
        (a sandbox sets it to the owner's cache), otherwise the default under the real home.
        The test never creates or fetches the tool.
        """
        env = self.env()
        configured = os.environ.get("QG_TOOLS_DIR")
        if configured:
            env["QG_TOOLS_DIR"] = configured
        else:
            env["HOME"] = str(Path.home())
        return env

    def fake_git_failing_ls_files(self) -> dict[str, str]:
        bin_dir = self.base / "fake-bin"
        bin_dir.mkdir()
        real_git = shutil.which("git")
        assert real_git is not None
        script = bin_dir / "git"
        script.write_text(
            "#!/bin/bash\n"
            'for arg in "$@"; do\n'
            '  if [ "$arg" = "ls-files" ]; then\n'
            '    echo "fatal: simulated enumeration failure" >&2\n'
            "    exit 128\n"
            "  fi\n"
            "done\n"
            f'exec "{real_git}" "$@"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def fake_git_failing_file_enumeration(self) -> dict[str, str]:
        """Fail only `ls-files` calls that do not include `-i`."""
        bin_dir = self.base / "fake-bin"
        bin_dir.mkdir()
        real_git = shutil.which("git")
        assert real_git is not None
        script = bin_dir / "git"
        script.write_text(
            "#!/bin/bash\n"
            "is_ls=0\n"
            "has_i=0\n"
            'for arg in "$@"; do\n'
            '  if [ "$arg" = "ls-files" ]; then is_ls=1; fi\n'
            '  if [ "$arg" = "-i" ]; then has_i=1; fi\n'
            "done\n"
            'if [ "$is_ls" = 1 ] && [ "$has_i" = 0 ]; then\n'
            '  echo "fatal: simulated file enumeration failure" >&2\n'
            "  exit 128\n"
            "fi\n"
            f'exec "{real_git}" "$@"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}


def output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr
