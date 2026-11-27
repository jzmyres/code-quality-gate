from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import signal
import socket
import string
import struct
import subprocess
import sys
import time
from dataclasses import replace
from functools import partial
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase

from quality_gate import adapters, checks, files, runner, secrets, tools
from quality_gate.policy import ConfigError, load_config

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


def _synthetic_credential(seed: int = 42) -> str:
    rng = random.Random(seed)
    return "ghp_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))


def _fragmented_record(fields: bytes) -> bytes:
    head, tail = b'{"padding":"', b'",\n'
    padding = b"a" * (124_800 - len(head + tail))
    return head + padding + tail + b" " * 300 + fields + b"\n}\n"


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
                Path(sys.executable), self.repo, self.evidence, selected, 600,
                open_parent=files._parent_fd, run=launch,
            )
            self.assertEqual(stderr.getvalue(), first.stdout + first.stderr)
        self.assertIs(result, first)
        targets = [call.args[0][call.args[0].index("--") + 1:] for call in launch.call_args_list]
        self.assertEqual(targets, [selected[:-1], selected[-1:]])

    def _provenance_fixture(
        self, *, declare_in_trusted: bool = True, tracked_payload: bool = True,
        pointer: str = "/pack/0/tokens_sha256", payload: bytes = struct.pack("<4q", 7, 31, 151, 4),
    ) -> tuple[Path, Path, str]:
        binary = self._require_scanner()
        digest = hashlib.sha256(payload).hexdigest()
        base = BASE_CONFIG + """
[[rule]]
pattern = "*.json"
class = "config"
reason = "report fixtures"

[[rule]]
pattern = "*.raw"
class = "config"
reason = "payload fixtures"
""" + DECLARATION
        declaration = f"""
[[checks.secrets.sha256_provenance]]
record = "report.json"
pointer = "{pointer}"
payload = "pack.raw"
payload_sha256 = "{digest}"
"""
        if declare_in_trusted:
            self.write_config(base + declaration)
        else:
            self.write_config(base)
        self.add_file("report.json", self._digest_record(digest))
        if tracked_payload:
            self.add_file("pack.raw", payload)
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        self.write_config(base + declaration)
        if not tracked_payload:
            self.add_file("pack.raw", payload)
        return binary, trusted, digest

    @staticmethod
    def _digest_record(digest: str, **extra: str) -> str:
        return json.dumps(
            {"Ω": "π", "pack": [{"tokens_sha256": digest}], **extra}, ensure_ascii=False,
        )

    def _run_provenance(
        self, binary: Path, trusted: Path | None, status: int, verified: int | None,
        *, repo: Path | None = None,
    ):
        trust_args = ["--only", "secrets"] if trusted is None else ["--policy-from", str(trusted)]
        result = self.run_qg_process(
            "check", "--json", *trust_args, repo=repo,
            env={"QG_TOOLS_DIR": str(binary.parent.parent)},
        )
        self.assertEqual(result.returncode, status, result.stderr)
        check = self.check_by_id(self.parse_json(result), "secrets")
        self.assertEqual((check.get("measurement") or {}).get("verified_sha256_provenance"), verified)
        return result, check

    def _git_fixture(self, filename: str = "proofs/old.raw") -> tuple[secrets.GitPayload, str]:
        source = b"synthetic historical provenance bytes\x00"
        self.add_file(filename, source)
        self.add_file("proofs/other.raw", b"an independent synthetic negative control")
        (self.repo / "proofs/linked.raw").symlink_to("old.raw")
        self.commit_all()
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        blob = self.git("rev-parse", f"{commit}:{filename}").stdout.strip()
        return secrets.GitPayload(filename, commit, blob, len(source)), hashlib.sha256(source).hexdigest()

    def _declare_git_proof(
        self, operand: secrets.GitPayload, digest: str, data: str, *, archive: bool = False,
    ) -> Path:
        name = "report.json.gz" if archive else "report.json"
        original = data.encode()
        content = gzip.compress(original, mtime=0) if archive else original
        self.add_file(name, content)
        base = BASE_CONFIG + DECLARATION + """
[[rule]]
pattern = "*.json*"
class = "config"
reason = "synthetic report fixtures"

[[rule]]
pattern = "*.raw"
class = "config"
reason = "synthetic historical operands"
"""
        operand_fields = (
            f'path = "{operand.path}", commit = "{operand.commit}", '
            f'blob = "{operand.blob}", size = {operand.size}'
        )
        declaration = f"""
[[checks.secrets.sha256_provenance]]
record = "{name}"
pointer = "/pack/0/tokens_sha256"
payload = {{ {operand_fields} }}
payload_sha256 = "{digest}"
"""
        if archive:
            declaration += f'compressed_sha256 = "{hashlib.sha256(content).hexdigest()}"\n'
            declaration += f'decoded_sha256 = "{hashlib.sha256(original).hexdigest()}"\n'
        self.write_config(base + declaration)
        self.commit_all()
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        return self.trusted_directory(revision, name=f"trusted-{revision}")

    def test_git_proof_uses_old_bytes_in_no_local_clone_and_keeps_other_findings(self) -> None:
        binary = self._require_scanner()
        operand, digest = self._git_fixture(":(top)old operand.raw")
        trusted = self._declare_git_proof(operand, digest, self._digest_record(digest))
        self.add_file(operand.path, b"new tracked bytes")
        self.commit_all()
        clone = self.base / "fresh"
        self.git("clone", "--no-local", "--single-branch", "--no-tags", str(self.repo), str(clone))
        self.assertFalse((clone / ".git/objects/info/alternates").exists())
        self.assertEqual((clone / operand.path).read_bytes(), b"new tracked bytes")
        result, _ = self._run_provenance(binary, trusted, 0, 1, repo=clone)
        self.assertNotIn(digest, result.stdout + result.stderr)

        (clone / operand.path).unlink()
        adjacent, undeclared = _synthetic_credential(), _synthetic_credential(43)
        (clone / "report.json").write_text(self._digest_record(digest, adjacent=adjacent))
        (clone / "undeclared.json").write_text(self._digest_record(undeclared))
        result, check = self._run_provenance(binary, trusted, 1, 1, repo=clone)
        self.assertEqual(check["reason"], "Betterleaks reported 2 unresolved finding(s)")
        self.assertEqual(result.stderr.count("RuleID: github-pat"), 2)
        for value in (digest, adjacent, undeclared):
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_git_payload_requires_exact_regular_blob_and_size(self) -> None:
        operand, digest = self._git_fixture()
        linked_blob = self.git("rev-parse", "HEAD:proofs/linked.raw").stdout.strip()
        linked_size = len(os.readlink(self.repo / "proofs/linked.raw").encode())
        other = self.git("rev-parse", "HEAD:proofs/other.raw").stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", f"160000,{operand.commit},gitlink")
        self.git("commit", "-m", "synthetic gitlink")
        head = self.git("rev-parse", "HEAD").stdout.strip()
        reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
        self.assertEqual(reader.digest(operand), digest)
        for invalid in (
            replace(operand, commit="0" * 40), replace(operand, commit=operand.blob),
            replace(operand, path="proofs/missing.raw"), replace(operand, path="proofs"),
            replace(operand, path="proofs/linked.raw", blob=linked_blob, size=linked_size),
            replace(operand, commit=head, path="gitlink", blob=operand.commit),
            replace(operand, blob=other), replace(operand, size=operand.size + 1),
            replace(operand, size=secrets.MAX_GIT_PAYLOAD_BYTES + 1),
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(reader.digest(invalid))

    def test_git_payload_uses_the_repository_object_format(self) -> None:
        repo = self.base / "sha256"
        self.git("init", "--object-format=sha256", str(repo))
        self.repo = repo
        self.add_file("empty.raw", b"")
        self.commit_all()
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        blob = self.git("rev-parse", "HEAD:empty.raw").stdout.strip()
        self.assertEqual((len(commit), len(blob)), (64, 64))
        reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, repo, 60))
        payload = secrets.GitPayload("empty.raw", commit, blob, 0)
        self.assertEqual(reader.digest(payload), hashlib.sha256(b"").hexdigest())
        self.assertIsNone(reader.digest(replace(payload, commit="0" * 40, blob="1" * 40)))

    def test_git_payload_ignores_local_only_commits_grafts_and_replacements(self) -> None:
        operand, digest = self._git_fixture()
        self.add_file("proofs/new.raw", b"head is a separate descendant")
        self.commit_all()
        local = self.git("commit-tree", f"{operand.commit}^{{tree}}", "-m", "local only").stdout.strip()
        changed = replace(operand, commit=local)
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("branch", "local-only", local)
        reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
        self.assertIsNone(reader.digest(changed))
        self.git("replace", "--graft", head, local)
        self._verify_ignored_ancestry_override(head, changed, operand, digest)

        self.git("replace", "-d", head)
        self.add_file(".git/info/grafts", f"{head} {local}\n")
        self._verify_ignored_ancestry_override(head, changed, operand, digest)

    def _verify_ignored_ancestry_override(
        self, head: str, changed: secrets.GitPayload, operand: secrets.GitPayload, digest: str,
    ) -> None:
        self.git("merge-base", "--is-ancestor", changed.commit, head)
        reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
        self.assertIsNone(reader.digest(changed))
        self.assertEqual(reader.digest(operand), digest)

    def test_git_payload_respects_deadline_and_refuses_promisor_lookup(self) -> None:
        operand, _ = self._git_fixture()
        with mock.patch.object(adapters, "run", wraps=runner.run) as launch:
            reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
            with runner.check_deadline("secrets", time.monotonic() - 2, 1):
                self.assertIsNone(reader.digest(operand))
            launch.assert_not_called()
            self.git("config", "remote.promised.promisor", "true")
            reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
            self.assertIsNone(reader.digest(operand))
            launch.assert_called_once()
        self.assertIn("config", launch.call_args.args[0])
        self.assertEqual(launch.call_args.kwargs["env"]["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(launch.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")

    def test_git_payload_checks_its_sha_and_is_read_once_per_run(self) -> None:
        operand, digest = self._git_fixture()
        declarations = [
            secrets.Provenance("report.json", ("slot", index), operand, pin)
            for pin, index in ((digest, "0"), ("0" * 64, "1"), (digest, "2"))
        ]
        reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))
        with mock.patch.object(reader, "digest", wraps=reader.digest) as read:
            pinned = list(secrets._pinned_payloads(self.evidence, declarations, reader))
        self.assertEqual(pinned, [declarations[0], declarations[2]])
        read.assert_called_once_with(operand)

    def test_git_payload_keeps_gzip_and_json_coordinate_checks(self) -> None:
        binary = self._require_scanner()
        operand, digest = self._git_fixture()
        record = self._digest_record(digest)
        trusted = self._declare_git_proof(operand, digest, record, archive=True)
        self._run_provenance(binary, trusted, 0, 1)
        self.add_file("report.json.gz", gzip.compress(record.encode(), mtime=1))
        self._run_provenance(binary, trusted, 1, 0)

        for invalid in (
            json.dumps({"pack": [{"tokens_sha256": digest}] * 2}),
            record.replace('"tokens_sha256"', '"tokens_sha256": "placeholder", "tokens_sha256"'),
        ):
            trusted = self._declare_git_proof(operand, digest, invalid, archive=True)
            result, _ = self._run_provenance(binary, trusted, 1, 0)
            self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_trusted_payload_verifies_exact_json_scalar(self) -> None:
        binary, trusted, digest = self._provenance_fixture()
        result, check = self._run_provenance(binary, trusted, 0, 1)
        self.assertEqual(check["diagnostics"]["exit_code"], 3)
        self.assertNotIn(digest, result.stderr)
        self.assertNotIn(digest, result.stdout)

        credential = _synthetic_credential()
        self.add_file("report.json", self._digest_record(digest, padding="0" * 500, credential=credential))
        result, _ = self._run_provenance(binary, trusted, 1, 1)
        self.assertIn("RuleID: github-pat", result.stderr)
        self.assertNotIn("RuleID: generic-api-key", result.stderr)
        self.assertNotIn(credential, result.stdout + result.stderr)

    def test_fragment_local_columns_verify_exact_json_scalar(self) -> None:
        binary, trusted, digest = self._provenance_fixture(
            pointer="/toy.token_reader", payload=b"quality-gate synthetic provenance\n",
        )
        fields = f'"toy.token_reader": "{digest}"'.encode()
        record = _fragmented_record(fields)
        self.add_file("report.json", record)
        scanner = runner.run(
            [*secrets._scanner_argv(binary), "--exit-code=3", "--report-format=json",
             "--report-path=-", "--", "report.json"],
            cwd=self.repo, env={}, budget_seconds=60, capture_limit=None,
        )
        self.assertEqual(scanner.returncode, 3, scanner.stderr_text)
        finding, = json.loads(scanner.stdout)
        self.assertEqual((finding["StartLine"], finding["StartColumn"]), (2, 106))
        self.assertEqual(record.splitlines()[1].index(b"token_reader") + 1, 306)

        result, _ = self._run_provenance(binary, trusted, 0, 1)
        self.assertNotIn(digest, result.stdout + result.stderr)

        credential = _synthetic_credential()
        self.add_file("report.json", _fragmented_record(fields + f', "credential": "{credential}"'.encode()))
        result, _ = self._run_provenance(binary, trusted, 1, 1)
        self.assertIn("RuleID: github-pat", result.stderr)
        self.assertNotIn(credential, result.stdout + result.stderr)

        self.add_file("pack.raw", b"different payload")
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_fragment_local_column_can_coincide_with_another_match(self) -> None:
        binary, trusted, digest = self._provenance_fixture(pointer="/toy.token_reader")
        rng = random.Random(43)
        credential = "".join(rng.choices(string.ascii_letters + string.digits, k=64))
        first = f'"toy.token_reader": "{digest}",'.encode()
        second = f'"other.token_reader": "{credential}"'.encode()
        self.add_file("report.json", _fragmented_record(first.ljust(198) + second))

        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("Column: 106\nRuleID: generic-api-key", result.stderr)
        self.assertIn("Column: 306\nRuleID: generic-api-key", result.stderr)
        self.assertNotIn(credential, result.stdout + result.stderr)

        self.add_file("report.json", _fragmented_record(second))
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_overlapping_match_spans_are_ambiguous(self) -> None:
        prefix = b'tokens_sha256": "'
        span = prefix + b"x" * 64 + b'"'
        offset = len(span) - 1 - prefix.index(b'"')
        data = span[:offset] + span
        self.assertIsNone(secrets._unique_value(data, prefix, 0, len(data)))
        self.assertEqual(secrets._unique_value(data, prefix, 1, len(data)), offset + len(prefix))

    def test_nonmatching_payload_and_wrong_pointer_leave_findings(self) -> None:
        binary, trusted, digest = self._provenance_fixture()
        self.add_file("report.json", self._digest_record(digest).replace('"pack"', '"other"'))
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

        self.add_file("report.json", self._digest_record(digest))
        self.add_file("pack.raw", b"different payload")
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_same_digest_in_another_json_scalar_still_fails(self) -> None:
        binary, trusted, digest = self._provenance_fixture()
        self.add_file("report.json", json.dumps({
            "pack": [{"tokens_sha256": digest}, {"tokens_sha256": digest}],
        }))
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

        self.add_file("report.json", json.dumps({
            "other": {"tokens_sha256": digest}, "pack": [{"tokens_sha256": digest}],
        }))
        result, _ = self._run_provenance(binary, trusted, 1, 1)
        self.assertIn("RuleID: generic-api-key", result.stderr)
        self.assertNotIn(digest, result.stdout + result.stderr)

    def test_repeated_digest_verifies_only_declared_spans_with_two_record_parses(self) -> None:
        binary = self._require_scanner()
        payload = b"synthetic bytes shared by three recorded digests\x00"
        digest = hashlib.sha256(payload).hexdigest()
        self.add_file("pack.raw", payload)
        self.add_file("report.json", json.dumps(
            {"pack": [{"tokens_sha256": digest}] * 3}, indent=2,
        ))
        declarations = tuple(
            secrets.Provenance("report.json", ("pack", str(index), "tokens_sha256"), "pack.raw", digest)
            for index in (0, 2)
        )
        stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(stderr),
            mock.patch.object(secrets, "load_json", wraps=secrets.load_json) as parse,
        ):
            result = secrets.scan_verified(
                binary, self.repo, self.evidence, ("pack.raw", "report.json"), 60, declarations,
                tracked={"pack.raw"}, open_parent=files._parent_fd, run=runner.run,
            )
        self.assertEqual(result.child.execution, "completed")
        self.assertEqual((result.verified, result.unresolved), (2, 1))
        self.assertIn("Line: 7\n", stderr.getvalue())
        self.assertEqual(parse.call_count, 3)

    def test_duplicate_json_member_cannot_claim_provenance(self) -> None:
        binary, trusted, digest = self._provenance_fixture()
        self.add_file("report.json", self._digest_record(digest).replace(
            '"tokens_sha256"', '"tokens_sha256": "placeholder", "tokens_sha256"',
        ))
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_untracked_payload_leaves_finding(self) -> None:
        binary, trusted, _ = self._provenance_fixture(tracked_payload=False)
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_symlinked_payload_leaves_finding(self) -> None:
        binary, trusted, _ = self._provenance_fixture()
        payload = self.repo / "pack.raw"
        payload.rename(self.repo / "original.raw")
        payload.symlink_to("original.raw")
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_candidate_only_declarations_cannot_verify_a_finding(self) -> None:
        binary, trusted, _ = self._provenance_fixture(declare_in_trusted=False)
        for policy_source in (None, trusted):
            with self.subTest(policy_source=policy_source):
                result, _ = self._run_provenance(binary, policy_source, 1, None)
                self.assertRegex(result.stderr, r"(?m)^RuleID:\s+generic-api-key$")

    def _gzip_fixture(
        self, record: bytes, payload: bytes, *, decoded_pin: str | None = None, tracked: bool = True,
    ) -> tuple[Path, Path]:
        binary = self._require_scanner()
        archive = gzip.compress(record, mtime=0)
        self.write_config(BASE_CONFIG + DECLARATION + f"""
[[rule]]
pattern = "*.json.gz"
class = "config"
reason = "compressed report fixtures"

[[rule]]
pattern = "*.raw"
class = "config"
reason = "payload fixtures"

[[checks.secrets.sha256_provenance]]
record = "report.json.gz"
pointer = "/pack/0/tokens_sha256"
payload = "pack.raw"
payload_sha256 = "{hashlib.sha256(payload).hexdigest()}"
compressed_sha256 = "{hashlib.sha256(archive).hexdigest()}"
decoded_sha256 = "{decoded_pin or hashlib.sha256(record).hexdigest()}"
""")
        self.add_file("pack.raw", payload)
        if tracked:
            self.add_file("report.json.gz", archive)
        self.commit_all()
        if not tracked:
            self.add_file("report.json.gz", archive)
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        return binary, self.trusted_directory(revision, name=f"trusted-{revision}")

    def test_gzip_proof_requires_trust_and_both_captured_hashes(self) -> None:
        payload = b"gzip proof synthetic payload\x00"
        digest = hashlib.sha256(payload).hexdigest()
        record = self._digest_record(digest).encode()
        binary, trusted = self._gzip_fixture(record, payload)
        result, _ = self._run_provenance(binary, trusted, 0, 1)
        self.assertNotIn(digest, result.stdout + result.stderr)
        self._run_provenance(binary, None, 1, None)

        self.add_file("report.json.gz", gzip.compress(record, mtime=1))
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

        self.add_file("report.json.gz", gzip.compress(record, mtime=0))
        self.add_file("pack.raw", b"different payload")
        self._run_provenance(binary, trusted, 1, 0)

    def test_gzip_with_wrong_decoded_pin_or_untracked_archive_keeps_finding(self) -> None:
        payload = b"gzip proof synthetic payload\x00"
        record = self._digest_record(hashlib.sha256(payload).hexdigest()).encode()
        binary, trusted = self._gzip_fixture(record, payload, tracked=False)
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

        binary, trusted = self._gzip_fixture(record, payload, decoded_pin="0" * 64)
        result, _ = self._run_provenance(binary, trusted, 1, 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_gzip_proof_keeps_same_line_and_nested_findings(self) -> None:
        payload = b"gzip proof synthetic payload\x00"
        digest = hashlib.sha256(payload).hexdigest()
        credential = _synthetic_credential()
        nested_credential = _synthetic_credential(43)
        nested = base64.b64encode(f'token = "{nested_credential}"'.encode()).decode()
        record = self._digest_record(digest, credential=credential, embedded=nested).encode()
        binary, trusted = self._gzip_fixture(record, payload)
        result, check = self._run_provenance(binary, trusted, 1, 1)
        self.assertEqual(check["reason"], "Betterleaks reported 2 unresolved finding(s)")
        self.assertEqual(result.stderr.count("RuleID: github-pat"), 2)
        for value in (digest, credential, nested_credential, nested):
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_ambiguous_and_duplicate_json_gzip_coordinates_keep_findings(self) -> None:
        payload = b"gzip proof synthetic payload\x00"
        digest = hashlib.sha256(payload).hexdigest()
        for record in (
            json.dumps({"pack": [{"tokens_sha256": digest}] * 2}).encode(),
            self._digest_record(digest).replace(
                '"tokens_sha256"', '"tokens_sha256": "placeholder", "tokens_sha256"',
            ).encode(),
            self._digest_record(digest, invalid="replace").encode().replace(b"replace", b"\xff"),
        ):
            with self.subTest(record=record):
                binary, trusted = self._gzip_fixture(record, payload)
                result, _ = self._run_provenance(binary, trusted, 1, 0)
                self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_gzip_reader_rejects_corruption_extra_members_and_size_overruns(self) -> None:
        record = b'{"record": "synthetic"}\n'
        archive = gzip.compress(record, mtime=0)
        path = self.evidence / "report.json.gz"
        for invalid in (b"plain text", archive[:-1], archive + archive, archive + b"\x00",
                        archive[:-8] + b"\x00" * 4 + archive[-4:]):
            with self.subTest(invalid=invalid):
                path.write_bytes(invalid)
                self.assertIsNone(secrets._read_gzip_record(path))

        path.write_bytes(archive)
        with mock.patch.object(secrets, "_MAX_COMPRESSED_BYTES", len(archive) - 1):
            self.assertIsNone(secrets._read_gzip_record(path))
        with mock.patch.object(secrets, "_MAX_RECORD_BYTES", len(record) - 1):
            self.assertIsNone(secrets._read_gzip_record(path))
        with (
            mock.patch.object(secrets, "_MAX_COMPRESSED_BYTES", len(archive)),
            mock.patch.object(secrets, "_MAX_RECORD_BYTES", len(record)),
        ):
            self.assertEqual(secrets._read_gzip_record(path).data, record)

    def test_gzip_replay_requires_one_complete_identical_row(self) -> None:
        finding = {
            "File": "report.json.gz", "RuleID": "generic-api-key", "StartLine": 1, "EndLine": 1,
            "StartColumn": 1, "EndColumn": 2, "Tags": [],
        }

        def child(rows):
            return runner.RunResult((), "completed", 3 if rows else 0, stdout=json.dumps(rows).encode())

        replay = mock.Mock(return_value=child([finding]))
        self.assertEqual(secrets._unique_direct_gzip_rows([finding], {0}, replay), {0})
        replay.assert_called_once_with(["report.json.gz"], "--max-archive-depth=1", "--max-decode-depth=0")
        self.assertEqual(secrets._unique_direct_gzip_rows([finding, finding], {0, 1}, replay), set())

        for invalid in (
            child([]), child([finding, finding]), child([dict(finding, Tags=["decoded:base64"])]),
            runner.RunResult((), "completed", 3, stdout=b"{}"),
            runner.RunResult((), "completed", 3, stdout=child([finding]).stdout, output_truncated=True),
            runner.RunResult((), "budget", None),
        ):
            with self.subTest(invalid=invalid):
                replay.return_value = invalid
                self.assertEqual(secrets._unique_direct_gzip_rows([finding], {0}, replay), set())

    def test_structured_report_must_be_complete_and_consistent(self) -> None:
        for code, report in ((0, b"bad"), (3, b"[]"), (0, b"[{}]"), (3, b"[{}]"), (1, b"[]")):
            with self.subTest(code=code, report=report):
                child = runner.RunResult((), "completed", code, stdout=report)
                with self.assertRaisesRegex(ValueError, "Betterleaks"):
                    secrets.scan_verified(
                        Path(sys.executable), self.repo, self.evidence, [], 60, (),
                        tracked=set(), open_parent=files._parent_fd, run=mock.Mock(return_value=child),
                    )

    def test_provenance_declarations_reject_invalid_rows(self) -> None:
        row = {
            "record": "report.json", "pointer": "/a~1b/~0c",
            "payload": "data.raw", "payload_sha256": "0" * 64,
        }
        valid = adapters._secrets_provenance({"sha256_provenance": [row]}, self.config_path, "secrets")
        self.assertEqual(valid[0].pointer, ("a/b", "~c"))
        for invalid in (
            {}, [42], [dict(row, record="report.txt")], [dict(row, payload="report.json")],
            [dict(row, payload="../data.raw")], [dict(row, payload_sha256="bad")],
            [dict(row, pointer="/a~2b")], [row, row],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                adapters._secrets_provenance({"sha256_provenance": invalid}, self.config_path, "secrets")

        compressed_pin, decoded_pin = "1" * 64, "2" * 64
        gzip_row = dict(
            row, record="report.json.gz", compressed_sha256=compressed_pin, decoded_sha256=decoded_pin,
        )
        gzip_proof, = adapters._secrets_provenance(
            {"sha256_provenance": [gzip_row]}, self.config_path, "secrets",
        )
        self.assertEqual(gzip_proof.gzip, secrets.GzipDigests(compressed_pin, decoded_pin))
        for invalid in (
            dict(row, record="report.json.gz"), dict(row, compressed_sha256=compressed_pin),
            dict(gzip_row, compressed_sha256="g" * 64), dict(gzip_row, decoded_sha256="A" * 64),
            {key: value for key, value in gzip_row.items() if key != "decoded_sha256"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                adapters._secrets_provenance({"sha256_provenance": [invalid]}, self.config_path, "secrets")

    def test_git_payload_declarations_reject_invalid_origin_and_duplicate_pointer(self) -> None:
        operand = dict(path="proofs/file.raw", commit="0" * 40, blob="1" * 40, size=10)
        row = dict(record="report.json", pointer="/tokens_sha256", payload=operand, payload_sha256="2" * 64)
        parsed, = adapters._secrets_provenance({"sha256_provenance": [row]}, self.config_path, "secrets")
        self.assertEqual(parsed.payload, secrets.GitPayload(**operand))
        for invalid in (
            dict(operand, path="../data.raw"), dict(operand, path="report.json"),
            dict(operand, path="proofs/*.raw"), dict(operand, commit="HEAD"),
            dict(operand, commit="a" * 39), dict(operand, blob="a" * 64),
            dict(operand, size=-1), dict(operand, size=True),
            dict(operand, size=secrets.MAX_GIT_PAYLOAD_BYTES + 1),
            dict(operand, alternate_path="extra.raw"),
            {key: value for key, value in operand.items() if key != "size"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                adapters._secrets_provenance(
                    {"sha256_provenance": [dict(row, payload=invalid)]}, self.config_path, "secrets",
                )
        with self.assertRaises(ConfigError):
            adapters._secrets_provenance(
                {"sha256_provenance": [row, dict(row, payload="proofs/local.raw")]},
                self.config_path, "secrets",
            )

    def test_unattested_match_locations_do_not_verify(self) -> None:
        digest = hashlib.sha256(b"example source").hexdigest()
        data = json.dumps({"tokens_sha256": digest}).encode()
        record = secrets._Record(data, (0,), {digest: [("tokens_sha256",)]})
        finding = {
            "RuleID": "generic-api-key", "File": "report.json", "Secret": "REDACTED",
            "Match": 'tokens_sha256": "REDACTED"', "StartLine": 1, "EndLine": 1,
            "StartColumn": 3, "EndColumn": len(data) - 1,
            "Attributes": {"path": "report.json", "resource": "fs.content"},
        }
        records = {"report.json": record}
        self.assertEqual(secrets._verified_finding_rows([finding], records), {0})
        observations = [finding, dict(finding, Secret="incorrect redaction"), finding]
        self.assertEqual(secrets._verified_finding_rows(observations, records), {0, 2})
        for changed in (
            {"EndLine": 2}, {"EndColumn": len(data) + 1}, {"StartColumn": 1},
            {"StartColumn": 4, "EndColumn": len(data)},
            {"Match": "unrelated"}, {"Match": 123},
            {"Match": 'REDACTEDtokens_sha256": "REDACTED"'},
            {"Secret": "incorrect redaction"}, {"Tags": ["decoded:base64"]},
            {"Attributes": {"path": "report.json", "resource": "fs.archive"}},
        ):
            with self.subTest(changed=changed):
                self.assertEqual(secrets._verified_finding_rows([dict(finding, **changed)], records), set())

    def test_oversized_record_gets_no_verification(self) -> None:
        declaration = secrets.Provenance("report.json", ("tokens_sha256",), "pack.raw", "0" * 64)
        path = declaration.record
        (self.evidence / path).write_text("{}", encoding="utf-8")
        with mock.patch.object(secrets, "_MAX_RECORD_BYTES", 1):
            self.assertEqual(secrets._verified_records(self.evidence, [path], {path: [declaration]}), {})
