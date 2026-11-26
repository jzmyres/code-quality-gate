from __future__ import annotations

import contextlib
import io
import json
import os
import random
import shutil
import signal
import socket
import string
import subprocess
import sys
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase

from quality_gate import adapters, checks, runner, secrets, tools
from quality_gate.policy import load_config

DECLARATION = """
[checks.secrets]
adapter = "secrets"
tier = 1
enforcement = "enforced"
"""

BLOCK_INTERNET = """
import ctypes
import os
import socket
import sys

class Argument(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

seccomp = ctypes.CDLL("libseccomp.so.2")
seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
seccomp.seccomp_init.restype = ctypes.c_void_p
seccomp.seccomp_rule_add_array.argtypes = [
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Argument),
]
seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
filter_context = seccomp.seccomp_init(0x7fff0000)
assert filter_context
syscall = seccomp.seccomp_syscall_resolve_name(b"socket")
assert syscall >= 0
for family in (socket.AF_INET, socket.AF_INET6):
    comparison = Argument(0, 4, family, 0)
    assert seccomp.seccomp_rule_add_array(filter_context, 0x80000000, syscall, 1, comparison) == 0
assert seccomp.seccomp_load(filter_context) == 0
os.execv(sys.argv[1], sys.argv[1:])
"""


def _synthetic_credential() -> str:
    rng = random.Random(42)
    return "ghp_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))


class SecretsTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(BASE_CONFIG + DECLARATION)
        self.config = load_config(self.repo)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()

    def _require_scanner(self) -> Path:
        tool = tools.load_tools(GATE / "tools.lock.toml")["betterleaks"]
        if not tools._tool_binary(tool, tools._tools_dir()).exists():
            self.skipTest("pinned Betterleaks is absent; run python3 -I qg.py tools fetch")
        return tools.tool_binary("betterleaks").resolve()

    def _check(self, root: Path | None = None):
        result, stdout, stderr = self._check_bytes(root)
        return result, stdout, stderr.decode("utf-8")

    def _check_bytes(self, root: Path | None = None):
        stdout, stderr = io.StringIO(), io.BytesIO()
        stream = io.TextIOWrapper(stderr, encoding="utf-8", write_through=True)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stream):
            result = checks.run_check(
                root or self.repo, self.config, self.config.checks["secrets"], [], {},
                prefix="check: secrets", evidence_dir=self.evidence,
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def _plant(self, path: str, suffix: str = "") -> str:
        credential = _synthetic_credential()
        self.add_file(path, f'ordinary text\ntoken = "{credential}"{suffix}\n')
        return credential

    def test_unstaged_credential_in_committed_file_fails_without_value(self) -> None:
        self._require_scanner()
        self.add_file("nested/settings.txt", "ordinary text\n")
        self.commit_all()
        credential = self._plant("nested/settings.txt")
        self.assertEqual(self.git("diff", "--cached", "--name-only").stdout, "")

        result, stdout, stderr = self._check()
        self.assertEqual(result.outcome, "fail", stderr)
        self.assertFalse(result.is_satisfied())
        self.assertIn("path: nested/settings.txt", stderr)
        self.assertRegex(stderr, r"(?m)^Line:\s+2$")
        self.assertRegex(stderr, r"(?m)^RuleID:\s+github-pat$")
        self.assertNotIn(credential, stdout + stderr + json.dumps(result.to_json()))

    def test_stageable_credential_fails_with_candidate_controls_disabled(self) -> None:
        self._require_scanner()
        self.add_file(".betterleaksignore", "new.txt:github-pat:2\n")
        self.add_file(".betterleaks.toml", "invalid scanner config\n")
        self._plant("new.txt", " # betterleaks:allow")
        self.assertIn("?? new.txt", self.git("status", "--short").stdout)

        result, _, stderr = self._check()
        self.assertEqual(result.outcome, "fail", stderr)
        self.assertIn("path: new.txt", stderr)

    def test_fresh_gate_process_does_not_import_the_candidate_package(self) -> None:
        binary = self._require_scanner()
        marker = self.base / "candidate-imported"
        self.add_file("quality_gate/__init__.py", f"open({str(marker)!r}, 'w').close()\n")
        self.add_file("quality_gate/secrets.py", f"open({str(marker)!r}, 'w').close()\n")
        self._plant("new.md")

        completed = self.run_qg_process(
            "check", "--only", "secrets", "--json",
            cwd=self.repo, env={"QG_TOOLS_DIR": str(binary.parent.parent)},
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("path: new.md", completed.stderr)
        self.assertFalse(marker.exists())

    def test_gitignored_file_is_not_scanned_in_clean_tree(self) -> None:
        self._require_scanner()
        self.add_file(".gitignore", "private.txt\n")
        self.commit_all()
        self._plant("private.txt")
        self.assertEqual(self.git("status", "--short").stdout, "")

        result, _, stderr = self._check()
        self.assertEqual(result.outcome, "pass", stderr)
        self.assertNotIn("private.txt", stderr)

    def test_shipped_tree_has_no_findings(self) -> None:
        self._require_scanner()
        archive = shutil.copytree(
            GATE, self.base / "archive",
            ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__", ".ruff_cache"),
        )
        self.git("-C", str(archive), "init", "-q")
        self.git("-C", str(archive), "add", "-A")

        result, _, stderr = self._check(archive)
        self.assertEqual(result.outcome, "pass", stderr)

    def test_missing_and_wrong_hash_scanner_are_unsupported(self) -> None:
        cache = self.base / "tools"
        with mock.patch.dict(os.environ, {"QG_TOOLS_DIR": str(cache)}):
            result, _, stderr = self._check()
            self.assertEqual(result.outcome, "unsupported", stderr)
            self.assertIn("is not installed", stderr)
            binary = tools._tool_binary(tools.load_tools(GATE / "tools.lock.toml")["betterleaks"], cache)
            binary.parent.mkdir(parents=True)
            binary.write_text("wrong payload", encoding="utf-8")
            result, _, stderr = self._check()
            self.assertEqual(result.outcome, "unsupported", stderr)
            self.assertIn("payload digest mismatch", stderr)

    def test_verified_scanner_runs_from_a_relative_cache(self) -> None:
        binary = self._require_scanner()
        relative_cache = os.path.relpath(binary.parent.parent)
        with mock.patch.dict(os.environ, {"QG_TOOLS_DIR": relative_cache}):
            result, _, stderr = self._check()
        self.assertEqual(result.outcome, "pass", stderr)
        self.assertEqual(Path(result.diagnostics.argv[0]), binary)

    def test_verified_scanner_runs_offline_and_output_is_forwarded(self) -> None:
        binary = self._require_scanner()
        self._plant("settings.txt")
        blocker = [sys.executable, "-I", "-c", BLOCK_INTERNET]
        for family in (socket.AF_INET, socket.AF_INET6):
            command = [*blocker, sys.executable, "-I", "-c", f"import socket; socket.socket({int(family)})"]
            self.assertEqual(subprocess.run(command, cwd=self.base, check=False).returncode, -signal.SIGSYS)
        forwarded = []

        def offline_run(argv, **options):
            self.assertEqual(Path(argv[0]), binary)
            self.assertIn("--validation=false", argv)
            self.assertEqual(
                [arg for arg in argv if "update" in arg and arg.startswith("--")], [],
            )
            child = runner.run([*blocker, *argv], **options)
            self.assertEqual(child.returncode, 1, child.combined_text)
            forwarded.extend((child.stdout_text, child.stderr_text))
            return child

        with mock.patch.object(adapters, "run", side_effect=offline_run):
            result, _, stderr = self._check()
        self.assertEqual(result.outcome, "fail", stderr)
        self.assertIn("github-pat", stderr)
        self.assertEqual(stderr, "".join(forwarded))

    def test_invalid_utf8_filename_in_scanner_output_is_forwarded_byte_for_byte(self) -> None:
        self._require_scanner()
        filename = b"nested/settings-\xff.txt"
        self._plant(os.fsdecode(filename))

        forwarded = []

        def run_scanner(argv, **options):
            child = runner.run(argv, **options)
            forwarded.extend((child.stdout, child.stderr))
            return child

        with mock.patch.object(adapters, "run", side_effect=run_scanner):
            result, _, stderr = self._check_bytes()
        expected = b"".join(forwarded)
        self.assertEqual(result.outcome, "fail", stderr)
        self.assertIn(b"path: " + filename, expected)
        self.assertEqual(stderr, expected)

    def test_budget_termination_removes_copied_input(self) -> None:
        self.add_file("nested/settings.txt", "ordinary text\n")
        copied = self.base / "copied"
        binary = self.base / "scanner"
        binary.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\n"
            "import time\n"
            f"assert Path.cwd().parent == Path({str(self.evidence)!r})\n"
            "assert Path('nested/settings.txt').read_text() == 'ordinary text\\n'\n"
            f"Path({str(copied)!r}).touch()\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        with mock.patch.object(adapters, "tool_binary", return_value=binary), mock.patch.object(
            checks, "RATCHET_BUDGET_SECONDS", 1,
        ):
            result, _, stderr = self._check()
        self.assertEqual(result.execution, "budget", stderr)
        self.assertTrue(copied.is_file())
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_snapshot_error_fails_without_launching_scanner(self) -> None:
        self.add_file("settings.txt", "ordinary text\n")
        self.commit_all()
        target = self.repo / "settings.txt"
        target.unlink()
        os.mkfifo(target)
        context = adapters.AdapterContext(
            self.repo, self.config, self.config.checks["secrets"], [], {},
            "check: secrets", {}, self.evidence, inventory_files=[],
        )
        stderr = io.StringIO()
        with mock.patch.object(adapters, "tool_binary", return_value=Path(sys.executable)), mock.patch.object(
            adapters, "run",
        ) as launch, contextlib.redirect_stderr(stderr):
            result = adapters._run_secrets(context)
        self.assertEqual(result.outcome, "error", stderr.getvalue())
        self.assertIn("settings.txt: expected a regular file or symlink", stderr.getvalue())
        self.assertEqual(list(self.evidence.iterdir()), [])
        launch.assert_not_called()

    def test_later_clean_batch_does_not_erase_a_finding(self) -> None:
        selected = [f"source-{index:02}.txt" for index in range(secrets._MAX_FILES_PER_INVOCATION + 1)]
        for path in selected:
            self.add_file(path, "ordinary text\n")
        first = runner.RunResult(
            (), "completed", 1, stdout=b"redacted finding\n", stderr=b"scanned source-\xff.txt\n",
        )
        second = runner.RunResult((), "completed", 0)
        launch = mock.Mock(side_effect=[first, second])
        stderr = io.BytesIO()
        with contextlib.redirect_stderr(io.TextIOWrapper(stderr, encoding="utf-8")):
            result = secrets.scan(
                Path(sys.executable), self.repo, self.evidence, selected, 600, run=launch,
            )
            self.assertEqual(stderr.getvalue(), first.stdout + first.stderr)
        self.assertIs(result, first)
        targets = [call.args[0][call.args[0].index("--") + 1:] for call in launch.call_args_list]
        self.assertEqual(targets, [selected[:-1], selected[-1:]])
