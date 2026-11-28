"""Tests for the machine-readable check result and its decision."""
from __future__ import annotations

import contextlib
import errno
import os
import subprocess
import hashlib
import importlib
import io
import json
import sys
import time
import tomllib
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest import mock

from support import (
    BASE_CONFIG,
    GATE,
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)
from support import PYTHON_TEST_HEADER, stub_check_result
from test_python_crap import crap_config

sys.path.insert(0, str(GATE))
adapters = importlib.import_module("quality_gate.adapters")
files = importlib.import_module("quality_gate.files")
runner = importlib.import_module("quality_gate.runner")
cli = importlib.import_module("quality_gate.cli")
policy = importlib.import_module("quality_gate.policy")
checks = importlib.import_module("quality_gate.checks")
gate_result = importlib.import_module("quality_gate.gate_result")


def _parse_chain(raw, root, path, full_key):
    requires = policy._string(raw, "requires", path, f"{full_key}.requires")
    return adapters.ParsedSpec(
        SimpleNamespace(requires=requires), "chain/1", ("static",),
        requires=requires,
    )


def _run_chain(context):
    result = stub_check_result(context.check, 60)
    required = context.check.spec.requires
    if not context.prior[required].is_satisfied():
        result.outcome = "unsupported"
        result.reason = f"{required} did not pass"
    return result


CHAIN_STUB = adapters.AdapterDescriptor(
    "chain-stub", ("requires",), _parse_chain, _run_chain,
    runs_suite=False,
)


def _policy_with(names: tuple[str, ...], blocks: list[str]) -> str:
    """BASE_CONFIG's python class, running exactly NAMES and BLOCKS."""
    listed = ", ".join(json.dumps(name) for name in names)
    text = BASE_CONFIG.replace(
        'checks = ["smoke"]', f"checks = [{listed}]"
    )
    return text + "\n\n" + "\n\n".join(blocks) + "\n"


def _command_block(identifier: str, source: str) -> str:
    return "\n".join([
        f"[checks.{identifier}]",
        'adapter = "command"',
        "tier = 1",
        'enforcement = "enforced"',
        f"run = {json.dumps(['python3', '-c', source])}",
    ])


def _chain_block(identifier: str, requires: str) -> str:
    return "\n".join([
        f"[checks.{identifier}]",
        'adapter = "chain-stub"',
        "tier = 1",
        'enforcement = "enforced"',
        f'requires = "{requires}"',
    ])


def _parse_test_chain(raw, root, path, full_key):
    requires = policy._string(raw, "requires", path, f"{full_key}.requires")
    return adapters.ParsedSpec(
        SimpleNamespace(requires=requires), "chain/1", ("tests",),
        requires=requires,
    )


TEST_CHAIN_STUB = adapters.AdapterDescriptor(
    "test-chain-stub", ("requires",), _parse_test_chain, _run_chain,
    runs_suite=False,
)


def _test_chain_block(identifier: str, requires: str) -> str:
    return "\n".join([
        f"[checks.{identifier}]",
        'adapter = "test-chain-stub"',
        "tier = 1",
        'enforcement = "enforced"',
        f'requires = "{requires}"',
    ])


def _tests_command_block(
    identifier: str, source: str, enforcement: str = "enforced"
) -> str:
    return "\n".join([
        f"[checks.{identifier}]",
        'adapter = "command"',
        "tier = 1",
        f'enforcement = "{enforcement}"',
        f"run = {json.dumps(['python3', '-c', source])}",
        "tests_pattern = '^Ran ([0-9]+) tests? in'",
    ])


def _verification_block(baseline: str) -> str:
    return "\n".join([
        "[checks.verification]",
        'adapter = "verification"',
        "tier = 1",
        'enforcement = "enforced"',
        f'baseline = "{baseline}"',
    ])


class ResultTests(FixtureCase):
    def test_json_has_every_documented_field(self) -> None:
        self.commit_all()
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        for key in (
            "schema",
            "gate_version",
            "revision",
            "dirty",
            "policy_sha256",
            "decision",
            "checks",
            "obligations",
            "prune",
        ):
            self.assertIn(key, document)
        self.assertEqual(document["schema"], 3)
        self.assertEqual(document["decision"], "accepted")
        self.assertFalse(document["dirty"])
        self.assertEqual(
            document["revision"],
            self.git("rev-parse", "HEAD").stdout.strip(),
        )
        self.assertEqual(
            document["policy_sha256"],
            hashlib.sha256(self.config_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(document["gate_version"])
        check = self.check_by_id(document, "smoke")
        for key in (
            "id",
            "kind",
            "tier",
            "enforcement",
            "adapter",
            "evidence",
            "metric_version",
            "execution",
            "outcome",
            "satisfied",
            "caused_by",
            "duration_seconds",
            "budget_seconds",
            "diagnostics",
            "findings",
            "resolved_baseline_entries",
            "unmeasured_baseline_entries",
            "reason",
        ):
            self.assertIn(key, check)
        self.assertIsNone(check["reason"])
        self.assertEqual(check["kind"], "check")
        self.assertEqual(check["evidence"], ["tests"])
        self.assertEqual(check["execution"], "completed")
        self.assertEqual(check["outcome"], "pass")
        self.assertTrue(check["satisfied"])
        self.assertIsNone(check["caused_by"])
        self.assertIsInstance(check["duration_seconds"], float)
        self.assertEqual(check["budget_seconds"], 600)
        diagnostics = check["diagnostics"]
        for key in (
            "argv",
            "exit_code",
            "signal",
            "output_bytes",
            "output_tail",
            "output_truncated",
        ):
            self.assertIn(key, diagnostics)
        self.assertEqual(diagnostics["exit_code"], 0)
        self.assertIsNone(diagnostics["signal"])
        self.assertIsInstance(diagnostics["output_bytes"], int)
        self.assertIsInstance(diagnostics["output_tail"], str)
        self.assertEqual(check["measurement"], {"tests": 1})
        for name in ("inventory", "hygiene"):
            builtin = self.check_by_id(document, name)
            self.assertEqual(builtin["kind"], name)
            self.assertEqual(builtin["outcome"], "pass")
            self.assertTrue(builtin["satisfied"])
        obligation = document["obligations"][0]
        self.assertIsNone(obligation["caused_by"])
        self.assertEqual(obligation["class"], "python")
        self.assertEqual(obligation["tier"], 1)
        self.assertEqual(obligation["status"], "satisfied")
        self.assertEqual(obligation["checks"], ["smoke"])
        self.assertEqual(obligation["required"], ["tests"])

    def test_dirty_tracks_a_changed_tree(self) -> None:
        self.commit_all()
        self.add_file("a.py", "print('changed')\n")
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertTrue(document["dirty"])

    def test_enforced_failure_is_rejected_and_exits_one(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "import sys; sys.exit(1)"]',
            )
        )
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 1, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["outcome"], "fail")
        self.assertNotIn("check:", result.stdout)

    def test_lint_only_class_leaves_tier_one_unsatisfied(self) -> None:
        self.write_config(
            BASE_CONFIG.replace("tests_pattern = '(\\d+)'\n", "")
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["evidence"], ["static"])
        self.assertTrue(check["satisfied"])
        obligation = document["obligations"][0]
        self.assertEqual(obligation["status"], "unsatisfied")
        self.assertEqual(obligation["checks"], [])
        self.assertIsNone(obligation["caused_by"])
        self.assertIn(
            "check: failed (obligation python tier 1)", result.stderr
        )
        self.assertNotIn("check: consequences", result.stderr)

    def test_advisory_failure_is_accepted_with_exceptions(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'enforcement = "enforced"', 'enforcement = "advisory"'
            ).replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "import sys; sys.exit(1)"]',
            )
            + '\n[[not_applicable]]\nclass = "python"\ntier = 1\n'
            'reason = "the only tier-1 check is advisory in this fixture"\n'
        )
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["outcome"], "fail")

    def test_baseline_exception_is_accepted_with_exceptions(self) -> None:
        self.write_config(with_clones())
        self.add_file(
            "quality-gate-clones.toml",
            baseline_text(
                [
                    {
                        "subject": "fp1",
                        "bound": 1,
                        "files": ["a.py", "b.py"],
                        "reason": "deliberate mirror",
                    }
                ]
            ),
        )
        self.add_file("b.py", "print('b')\n")
        env = self.install_fake_jscpd(
            sarif_report([("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])])
        )
        result = self.run_qg("check", "--json", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "fail")
        self.assertTrue(check["satisfied"])
        self.assertIn("ratchet findings", check["reason"])
        self.assertEqual(len(check["findings"]), 1)
        finding = check["findings"][0]
        for key in (
            "subject",
            "value",
            "bound",
            "threshold",
            "baseline_reason",
            "covered_by_baseline",
            "blocking",
            "location",
        ):
            self.assertIn(key, finding)
        self.assertTrue(finding["covered_by_baseline"])
        self.assertEqual(finding["subject"], "fp1")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], 1)
        self.assertEqual(finding["threshold"], 0)
        self.assertEqual(finding["baseline_reason"], "deliberate mirror")
        self.assertFalse(finding["blocking"])
        self.assertIn("a.py:1-8", finding["location"])

    def test_policy_error_with_json_is_one_error_document(self) -> None:
        self.write_config(BASE_CONFIG.replace("schema = 2\n", ""))
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 2, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "error")
        self.assertEqual(document["checks"], [])
        self.assertIn("schema", document["error"])
        self.assertIn("schema", result.stderr)

    def test_unknown_option_with_json_is_one_error_document(self) -> None:
        result = self.run_qg("check", "--json", "--unknown-option")
        self.assertEqual(result.returncode, 2, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["schema"], 3)
        self.assertEqual(document["decision"], "error")
        self.assertEqual(document["checks"], [])
        self.assertEqual(document["obligations"], [])
        self.assertIn("unrecognized arguments", document["error"])
        self.assertIn("unrecognized arguments", result.stderr)

    def test_usage_error_with_repo_equals_still_finds_policy(self) -> None:
        result = self.run_qg(
            f"--repo={self.repo}",
            "check",
            "--json",
            "--unknown-option",
            include_repo=False,
        )
        self.assertEqual(result.returncode, 2, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "error")
        self.assertEqual(
            document["policy_sha256"],
            hashlib.sha256(self.config_path.read_bytes()).hexdigest(),
        )

    def adapter_configs(self) -> dict[str, str]:
        pattern = json.dumps(r"Ran (\d+) tests")
        tests = (
            "\n[checks.tests]\nadapter = \"python_tests\"\ntier = 1\n"
            "enforcement = \"enforced\"\n"
            'run = ["{python}", "-m", "unittest"]\n'
            f"tests_pattern = {pattern}\n"
        )
        crap = (
            "\n[checks.crap]\nadapter = \"python_crap\"\ntier = 1\n"
            "enforcement = \"enforced\"\nrequires = \"tests\"\n"
            'baseline = "crap.toml"\n'
        )
        return {
            "command": BASE_CONFIG,
            "clones": with_clones(),
            "python_tests": BASE_CONFIG + tests,
            "python_crap": BASE_CONFIG + tests + crap,
        }

    def test_malformed_tool_lock_is_one_json_error_for_every_adapter(self) -> None:
        lock = self.base / "bad-lock.toml"
        lock.write_text('[jscpd]\nversion = "5.4.1"\n', encoding="utf-8")
        for name, text in self.adapter_configs().items():
            self.add_file(
                "quality-gate-clones.toml", baseline_text([], check="clones")
            )
            self.add_file(
                "crap.toml",
                baseline_text(
                    [], check="crap", metric_version="python-lines/1"
                ),
            )
            with self.subTest(adapter=name):
                self.write_config(text)
                stdout = io.StringIO()
                with mock.patch.object(
                    cli, "_default_lock_path", return_value=lock
                ):
                    with contextlib.redirect_stdout(stdout):
                        code = cli.main(
                            ["--repo", str(self.repo), "check", "--json"]
                        )
                self.assertEqual(code, 2, stdout.getvalue())
                document = json.loads(stdout.getvalue())
                self.assertEqual(document["decision"], "error")
                self.assertEqual(document["checks"], [])
                self.assertIn("bad-lock.toml", document["error"])

    def test_resolved_baseline_entry_is_in_the_result(self) -> None:
        self.write_config(with_clones())
        self.add_file(
            "quality-gate-clones.toml",
            baseline_text([{"subject": "gone", "bound": 1, "reason": "old"}]),
        )
        env = self.install_fake_jscpd(sarif_report([]))
        result = self.run_qg("check", "--json", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["resolved_baseline_entries"], ["gone"])


def _ledger_command_block(identifier: str, source: str, *arguments: str) -> str:
    return _command_block(identifier, source).replace(
        json.dumps(["python3", "-c", source]),
        json.dumps(["python3", "-c", source, *arguments]),
    )


class GateLedgerTests(FixtureCase):
    ledger_count = 0
    module_policy = """
[checks.module-contracts]
adapter = "module_contracts"
tier = 1
enforcement = "enforced"
shared_base = "HEAD"

[modules.source]
files = ["*.py"]
entry_points = []
allowed_dependencies = []
"""

    @property
    def ledger_path(self):
        return self.base / "evidence.jsonl"

    def gate_arguments(self, args, repo, include_repo):
        if args[0] == "check" and "--ledger" not in args:
            args = (*args, "--ledger", str(self.ledger_path))
        return super().gate_arguments(args, repo, include_repo)

    def read_ledger(self, *streams):
        for stream in streams:
            self.assertNotIn("qg-ledger: ", stream)
            self.assertNotIn('"run_id":', stream)
        self.assertTrue(self.ledger_path.is_file(), self.ledger_path)
        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        self.ledger_count += 1
        self.assertEqual(len(lines), self.ledger_count)
        record = json.loads(lines[-1])
        self.assertEqual(record["schema"], 1)
        self.assertTrue(record["run_id"])
        return record

    def expected_ids(self, *, only=None, policy_text=None):
        declared = tomllib.loads(policy_text or self.read_file("quality-gate.toml"))["checks"]
        builtins = {"inventory", "hygiene"}
        if "module-contracts" in declared:
            builtins.add("module-contracts")
        pending = list(declared if only is None else only)
        expected = set(builtins)
        while pending:
            identifier = pending.pop()
            if identifier in expected:
                continue
            expected.add(identifier)
            if "requires" in declared[identifier]:
                pending.append(declared[identifier]["requires"])
        return expected

    def assert_ids(self, record, expected):
        counts = Counter(row["id"] for row in record["checks"])
        missing = sorted(expected - counts.keys())
        extra = sorted(counts.keys() - expected)
        repeated = {name: count for name, count in counts.items() if count > 1}
        self.assertFalse(
            missing or extra or repeated, f"missing={missing}, extra={extra}, repeated={repeated}",
        )

    def assert_json_evidence(self, result, document, record):
        self.assertEqual(record["exit_status"], result.returncode)
        for key in ("decision", "gate_version", "policy_sha256"):
            self.assertEqual(record[key], document[key], key)
        self.assertEqual(
            record["exemptions"],
            [{"class": row["class"], "tier": row["tier"]}
             for row in document["obligations"] if row["status"] == "exempted"],
        )
        self.assertTrue(record["complete"])
        self.assertIsNone(record["termination"])
        self.assertEqual([row["id"] for row in record["checks"]], [row["id"] for row in document["checks"]])
        for row, check in zip(record["checks"], document["checks"], strict=True):
            with self.subTest(check=check["id"]):
                for key in (
                    "adapter", "metric_version", "execution", "outcome", "satisfied",
                    "location_coverage", "enforcement", "duration_seconds",
                ):
                    self.assertEqual(row[key], check[key], key)
                selected = check.get("selection")
                self.assertEqual(row["selection"], None if selected is None else {
                    key: list(selected[key]) for key in ("selected", "left_out")
                })
                self.assertTrue({"argv", "diagnostics", "reason"}.isdisjoint(row))

    def assert_identity(self, record, dirty=False):
        revision = self.git("rev-parse", "--verify", "HEAD^{commit}").stdout.strip()
        identity = {"revision": revision, "dirty": dirty}
        self.assertEqual(record["start"], identity)
        self.assertEqual(record["end"], identity)
        self.assertEqual(record["attribution_revision"], revision if dirty is False else None)

    def assert_result_identity(self, document, record):
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        status = subprocess.run(
            ["git", "--no-optional-locks", "status", "--porcelain"],
            cwd=self.repo, env=self.env(), capture_output=True, text=True, check=False,
        )
        dirty = bool(status.stdout.strip()) if status.returncode == 0 else None
        probe = gate_result._git
        if isinstance(probe, mock.Mock) and probe(self.repo, ["status", "--porcelain"]) is None:
            dirty = None
        self.assertEqual({"revision": document["revision"], "dirty": document["dirty"]},
                         {"revision": revision, "dirty": dirty})
        if record["end"]["revision"] is not None:
            self.assertEqual(record["end"]["revision"], revision)

    def assert_json_ledger(self, result, document, *, status=0):
        self.assertEqual(result.returncode, status, output(result))
        record = self.read_ledger(result.stdout, result.stderr)
        self.assert_ids(record, self.expected_ids())
        self.assert_json_evidence(result, document, record)
        return record

    def assert_identity_run(self, *args, dirty):
        result, document = self.run_json(*args)
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_ids(record, self.expected_ids())
        self.assert_identity(record, dirty=dirty)
        self.assert_result_identity(document, record)
        return record

    def test_discovery_preserves_runtime_and_undispatched_skip_takes_zero_seconds(self):
        argv = ["{python}", str(GATE / "quality_gate" / "test_shards.py"), "-s", "tests", "-j", "1"]
        self.write_config(_policy_with(("smoke", "suite", "lint"), [rf"""
[checks.suite]
adapter = "python_tests"
tier = 1
enforcement = "enforced"
run = {json.dumps(argv)}
tests_pattern = 'Ran (\d+) tests?'

[checks.lint]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "raise SystemExit(8)", "{{files}}"]
"""]))
        self.add_file("tests/test_discovery.py", PYTHON_TEST_HEADER + """
class Discovery(unittest.TestCase):
    def test_omitted(self):
        self.fail("outside affected scope")
""")
        self.commit_all()
        execute = checks._run_selected_check
        returned = {}

        def observe(root, config, check, *args, **kwargs):
            clock = mock.Mock(side_effect=(1.0, 2.0))
            timer = mock.patch.object(checks, "time", SimpleNamespace(monotonic=clock))
            with timer if check.id == "lint" else contextlib.nullcontext():
                result = execute(root, config, check, *args, **kwargs)
            returned[check.id] = result.duration_seconds
            return result

        with (
            mock.patch.object(cli, "_refuse_in_agent_sandbox"),
            mock.patch.object(
                adapters.python_tests, "coverage_prefix", return_value=[sys.executable, "-I", "-B"],
            ),
            mock.patch.object(checks, "_run_selected_check", side_effect=observe),
        ):
            result, document = self.run_json("--base", "HEAD")
        record = self.assert_json_ledger(result, document)
        for identifier in ("suite", "lint"):
            with self.subTest(identifier=identifier):
                row = self.check_by_id(record, identifier)
                self.assertEqual((row["execution"], row["outcome"]), ("not_run", "not_run"))
                self.assertEqual(row["duration_seconds"], round(returned[identifier], 6))
        suite = self.check_by_id(document, "suite")
        self.assertEqual(suite["executed"], [])
        self.assertEqual(list(suite["selection"]["left_out"]), ["test_discovery.Discovery.test_omitted"])
        self.assertGreater(returned["suite"], 0)
        self.assertEqual(returned["lint"], 0.0)

    def test_git_visible_dirty_inputs_are_ineligible(self):
        self.commit_all()
        self.git("config", "status.showUntrackedFiles", "no")
        for state in ("staged", "unstaged", "untracked"):
            with self.subTest(state=state):
                path = "untracked.py" if state == "untracked" else "a.py"
                self.add_file(path, "print('changed')\n")
                if state == "staged":
                    self.git("add", path)
                record = self.assert_identity_run("--base", "HEAD", dirty=True)
                self.assertIn(path, record["changed_paths"])
                if state != "untracked":
                    self.git("restore", "--source=HEAD", "--staged", "--worktree", path)

    def test_submodule_dirt_is_ineligible_with_ignore_all(self):
        source = self.base / "submodule-source"
        source.mkdir()
        for args in (("init", "-q"), ("commit", "-q", "--allow-empty", "-m", "fixture submodule")):
            subprocess.run(["git", *args], cwd=source, env=self.env(), check=True, capture_output=True)
        self.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(source), "vendor")
        self.write_config(BASE_CONFIG + """
[[rule]]
pattern = "vendor"
class = "config"
reason = "Pinned submodule"

[[rule]]
pattern = ".gitmodules"
class = "config"
reason = "Submodule configuration"
""")
        self.commit_all()
        self.git("config", "submodule.vendor.ignore", "all")
        self.add_file("vendor/untracked.py", "print('submodule dirt')\n")
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assert_identity_run(dirty=True)

    def test_index_flags_make_apparently_clean_inputs_unknown(self):
        self.commit_all()
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", f"--{flag}", "a.py")
                self.add_file("a.py", "print('hidden change')\n")
                self.assertEqual(self.git("status", "--porcelain").stdout, "")
                self.assert_identity_run(dirty=None)
                self.git("update-index", f"--no-{flag}", "a.py")
                self.git("restore", "a.py")

    def test_failed_identity_probes_make_clean_inputs_unknown(self):
        self.commit_all()
        execute = gate_result._git
        for command in ("status", "ls-files"):
            with self.subTest(probe=command):
                def fail_probe(root, args, command=command):
                    return None if args[0] == command else execute(root, args)

                with mock.patch.object(gate_result, "_git", side_effect=fail_probe):
                    self.assert_identity_run(dirty=None)

    def test_noncommit_head_is_unknown_to_the_ledger_and_cli_json(self):
        self.commit_all()
        blob = self.git("rev-parse", "HEAD:a.py").stdout.strip()
        self.add_file(".git/HEAD", f"{blob}\n")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), blob)
        result, document = self.run_json()
        record = self.read_ledger(result.stdout, result.stderr)
        self.assert_ids(record, self.expected_ids())
        self.assertIsNone(record["start"]["revision"])
        self.assertIsNone(record["end"]["revision"])
        self.assertIsNone(record["attribution_revision"])
        self.assert_result_identity(document, record)

    def test_clean_full_text_and_json_rerun_with_enabled_builtin_and_exemption(self):
        self.write_config(BASE_CONFIG + self.module_policy + """
[[not_applicable]]
class = "python"
tier = 1
reason = "fixture exemption"
""")
        self.commit_all()
        text_result = self.run_qg_process("check")
        first = self.read_ledger(text_result.stdout, text_result.stderr)
        result, document = self.run_json()
        second = self.read_ledger(result.stdout, result.stderr)
        for invocation, record in ((text_result, first), (result, second)):
            self.assertEqual(invocation.returncode, 0, output(invocation))
            self.assert_ids(record, self.expected_ids())
            self.assert_identity(record)
            self.assertEqual(record["scope"], "full")
            self.assertIsNone(record["resolved_base"])
            self.assertEqual(
                self.check_by_id(record, "module-contracts")["resolved_base"], record["start"]["revision"],
            )
            self.assertEqual(record["exemptions"], [{"class": "python", "tier": 1}])
        self.assertIn("check: passed", text_result.stdout)
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assert_json_evidence(result, document, second)

    def test_dirty_only_run_records_prerequisites_and_the_policy_bytes_used(self):
        original = _policy_with(("smoke", "first", "last", "unselected"), [
            _chain_block("first", "smoke"), _chain_block("last", "first"),
            _command_block("unselected", "raise SystemExit(8)"),
        ])
        self.write_config(original)
        self.commit_all()
        self.add_file("a.py", "print('dirty')\n")
        execute = checks._run_selected_check

        def replace_policy(*args, **kwargs):
            self.write_config(original + "\n# replaced during execution\n")
            return execute(*args, **kwargs)

        with (
            mock.patch.dict(adapters.ADAPTERS, {CHAIN_STUB.name: CHAIN_STUB}),
            mock.patch.object(checks, "_run_selected_check", side_effect=replace_policy),
        ):
            result, document = self.run_json("--only", "last")
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_ids(record, self.expected_ids(only=["last"], policy_text=original))
        self.assert_json_evidence(result, document, record)
        self.assert_identity(record, dirty=True)
        self.assertEqual(record["scope"], "partial")
        self.assertEqual(record["selected"], ["smoke", "first", "last"])
        self.assertEqual(record["policy_sha256"], hashlib.sha256(original.encode()).hexdigest())

    def test_trusted_affected_uses_merge_base_and_records_final_trust_decision(self):
        self.write_config(_policy_with(("smoke", "lint"), ["""
[checks.lint]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "print('lint')", "{files}"]
"""]))
        self.add_file("tools.lock.toml", "")
        self.commit_all()
        merge_base = self.git("rev-parse", "HEAD").stdout.strip()
        trusted = self.trusted_directory("HEAD")
        self.git("switch", "-c", "other")
        self.add_file("README.md", "# other branch\n")
        self.commit_all("change on other branch")
        self.git("switch", "main")
        options = ("--policy-from", str(trusted), "--base", "other")
        result = self.run_qg_process("check", *options)
        first = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("check: lint: not run", result.stdout)
        self.assertEqual((first["decision"], first["exit_status"]), ("partial", 0))
        self.assert_identity(first)
        self.assert_ids(first, self.expected_ids())
        skip = self.check_by_id(first, "lint")
        self.assertEqual(
            (skip["execution"], skip["outcome"], skip["duration_seconds"]), ("not_run", "not_run", 0.0),
        )
        self.assertEqual(skip["selection"], {"selected": [], "left_out": ["a.py"]})
        result, document = self.run_json(*options)
        clean = self.read_ledger(result.stdout, result.stderr)
        self.assert_ids(clean, self.expected_ids())
        self.assert_identity(clean)
        self.assert_json_evidence(result, document, clean)
        self.assertEqual(self.check_by_id(clean, "lint")["execution"], "not_run")
        policy_text = self.read_file("quality-gate.toml")
        self.write_config(policy_text + "\n# unauthorized change\n")
        result, document = self.run_json(*options)
        second = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["schema"], 4)
        self.assertEqual(second["decision"], "blocked")
        notices = result.stderr.splitlines()
        self.assertTrue(notices[-2].startswith("check: protected input "), result.stderr)
        self.assertTrue(notices[-1].startswith("check: blocked:"), result.stderr)
        self.assertNotIn("check: partial run passed", result.stderr)
        self.assertEqual(second["policy_sha256"], hashlib.sha256(policy_text.encode()).hexdigest())
        self.assert_ids(second, self.expected_ids(policy_text=policy_text))
        self.assert_identity(second, dirty=True)
        self.assert_json_evidence(result, document, second)
        self.assertEqual(first["changed_paths"], [])
        self.assertEqual(second["changed_paths"], ["quality-gate.toml"])
        for record in (first, clean, second):
            self.assertEqual(record["scope"], "affected")
            self.assertEqual(record["base"], "other")
            self.assertEqual(record["resolved_base"], merge_base)

    def test_baseline_covered_failure_preserves_its_subject_ranges_and_expiry(self):
        self.write_config(with_clones())
        self.add_file("b.py", "print('b')\n")
        self.add_file("quality-gate-clones.toml", baseline_text([{
            "subject": "fp1", "bound": 1, "files": ["a.py", "b.py"],
            "reason": "fixture exception", "expires": "2099-01-01",
        }]))
        ranges = [("a.py", 1, 3), ("b.py", 2, 5)]
        env = self.install_fake_jscpd(sarif_report([("fp1", ranges)]))
        result, document = self.run_json(env=env)
        record = self.assert_json_ledger(result, document)
        self.assertIsNone(record["start"]["revision"])
        self.assertIsNone(record["end"]["revision"])
        self.assertIsNone(record["attribution_revision"])
        self.assertEqual(record["decision"], "accepted_with_exceptions")
        row = self.check_by_id(record, "clones")
        self.assertEqual((row["outcome"], row["satisfied"]), ("fail", True))
        self.assertEqual(len(row["findings"]), 1)
        finding = row["findings"][0]
        original = self.check_by_id(document, "clones")["findings"][0]
        for key in ("subject", "locations", "covered_by_baseline", "expired", "blocking"):
            self.assertEqual(finding[key], original[key], key)
        self.assertEqual(finding["subject"], "fp1")
        self.assertTrue(finding["covered_by_baseline"])
        self.assertFalse(finding["expired"])
        self.assertEqual(finding["baseline_expires"], "2099-01-01")
        self.assertEqual(finding["locations"], [
            {"path": path, "start_line": start, "end_line": end} for path, start, end in ranges
        ])

    def test_adapter_and_builtin_findings_retain_available_locations(self):
        self.write_config(_policy_with(("smoke", "comments"), ["""
[checks.comments]
adapter = "comments"
tier = 1
enforcement = "enforced"
"""]) + self.module_policy.replace('"*.py"', '"missing/*.py"'))
        self.add_file("a.py", "print('a')\n# private comment marker\n")
        self.commit_all()
        result, document = self.run_json()
        record = self.assert_json_ledger(result, document, status=1)
        findings = self.check_by_id(record, "module-contracts")["findings"]
        self.assertEqual({row["rule"]: row["locations"] for row in findings}, {
            "unused-pattern": None,
            "uncovered-file": [{"path": "a.py", "start_line": None, "end_line": None}],
        })
        rows = self.check_by_id(record, "comments")["findings"]
        self.assertEqual(rows, [{"locations": [{"path": "a.py", "start_line": 2, "end_line": 2}]}])
        self.assertIn("private comment marker", result.stderr)
        self.assertNotIn("private comment marker", json.dumps(record))

    def test_interruption_keeps_completed_checks_and_times_only_the_active_attempt(self):
        self.write_config(_policy_with(("smoke", "abort", "unreached"), [
            _command_block("abort", "pass"), _command_block("unreached", "pass"),
        ]))
        self.commit_all()
        execute = checks.run_check
        initial = self.git("rev-parse", "HEAD").stdout.strip()

        def interrupt(root, config, check, *args, **kwargs):
            if check.id == "abort":
                self.git("commit", "--allow-empty", "-m", "move HEAD during check")
                time.sleep(0.02)
                raise policy.GateError("injected interruption")
            return execute(root, config, check, *args, **kwargs)

        with mock.patch.object(checks, "run_check", side_effect=interrupt):
            result, document = self.run_json()
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(document["error"], "injected interruption")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(record["exit_status"], 1)
        self.assertEqual(record["decision"], "error")
        self.assertFalse(record["complete"])
        self.assert_ids(record, self.expected_ids() - {"unreached"})
        self.assertEqual(record["start"], {"revision": initial, "dirty": False})
        ending_revision = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(record["end"], {"revision": ending_revision, "dirty": False})
        self.assertNotEqual(record["start"], record["end"])
        self.assertIsNone(record["attribution_revision"])
        completed = self.check_by_id(record, "smoke")
        self.assertEqual((completed["execution"], completed["outcome"]), ("completed", "pass"))
        self.assertGreater(completed["duration_seconds"], 0)
        attempt = self.check_by_id(record, "abort")
        self.assertEqual(attempt["execution"], "interrupted")
        self.assertEqual(attempt["termination"], "GateError")
        self.assertIsNone(attempt["outcome"])
        self.assertIsNone(attempt["satisfied"])
        self.assertGreaterEqual(attempt["duration_seconds"], 0.02)

    def test_cleanup_failure_preserves_all_results(self):
        remove_directory = checks._remove_run_directory

        def fail_cleanup(directory):
            self.addCleanup(directory.cleanup)
            with mock.patch.object(directory, "cleanup", side_effect=OSError("denied")):
                remove_directory(directory)

        with mock.patch.object(checks, "_remove_run_directory", side_effect=fail_cleanup):
            result, document = self.run_json(env={"TMPDIR": str(self.base)})
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("cannot remove the run directory", document["error"])
        self.assert_ids(record, self.expected_ids())
        self.assertFalse(record["complete"])
        self.assertEqual(record["termination"], "RunCleanupError")
        self.assertEqual(record["exit_status"], 2)
        self.assertTrue(all(row["outcome"] == "pass" for row in record["checks"]))

    def test_preflight_refusal_has_no_ledger(self):
        refused, document = self.run_json("--only", "missing")
        self.assertEqual(refused.returncode, 2, output(refused))
        self.assertIn("unknown check", document["error"])
        self.assertFalse(self.ledger_path.exists())
        successful, document = self.run_json("--only", "smoke")
        self.assertEqual(successful.returncode, 0, output(successful))
        record = self.read_ledger(successful.stdout, successful.stderr)
        self.assert_ids(record, self.expected_ids(only=["smoke"]))
        self.assert_json_evidence(successful, document, record)

    def test_builtin_ids_are_reserved_by_the_policy_loader(self):
        for identifier in ("inventory", "hygiene", "module-contracts"):
            with self.subTest(identifier=identifier):
                self.write_config(_policy_with(("smoke", identifier), [_command_block(identifier, "pass")]))
                with self.assertRaises(policy.ConfigError) as raised:
                    policy.load_config(self.repo)
                self.assertIn(f"configured check {identifier!r}", str(raised.exception))
                self.assertIn(f"built-in check {identifier!r}", str(raised.exception))
        self.write_config(BASE_CONFIG + self.module_policy)
        self.commit_all()
        result, document = self.run_json()
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_ids(record, self.expected_ids())
        self.assert_json_evidence(result, document, record)

    def test_unwritable_ledger_path_preserves_the_gate_exit_status(self):
        self.ledger_path.mkdir()
        prefix = f"check: cannot write the gate ledger to {self.ledger_path}:"
        for args in ((), ("--json",)):
            with self.subTest(args=args):
                log = self.merged_check(*args, status=2)
                self.assertNotIn("check: passed", log)
                message = log.splitlines()[-1]
                self.assertTrue(message.startswith(prefix), message)
                self.assertIn(os.strerror(errno.EISDIR), message)
        result, document = self.run_json()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertTrue(document["error"].startswith(prefix), document["error"])
        self.assertEqual(result.stderr.splitlines()[-1], document["error"])
        self.ledger_path.rmdir()
        successful, document = self.run_json()
        record = self.read_ledger(successful.stdout, successful.stderr)
        self.assert_ids(record, self.expected_ids())
        self.assert_json_evidence(successful, document, record)

    def merged_check(self, *args, status=0):
        argv = self.gate_arguments(("check", *args), repo=None, include_repo=True)
        log = subprocess.run(
            [sys.executable, "-I", "-B", str(GATE / "qg.py"), *argv],
            env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        )
        self.assertEqual(log.returncode, status, log.stdout)
        return log.stdout

    def test_partial_verdict_follows_obligations_notice(self):
        notice = 'check: obligations not evaluated ("python" tier 1)'
        verdict = "check: partial run passed (3 checks)"
        for args in ((), ("--json",)):
            with self.subTest(args=args):
                log = self.merged_check("--only", "smoke", *args)
                self.assertEqual(log.splitlines()[-2:], [notice, verdict])
                record = self.read_ledger(log)
                self.assert_ids(record, self.expected_ids(only=["smoke"]))

    def test_ledger_precedes_the_verdict_on_success(self):
        report = checks._print_check_report

        def verify_ledger(*args):
            record = self.read_ledger()
            self.assert_ids(record, self.expected_ids())
            self.assertEqual((record["decision"], record["exit_status"]), ("accepted", 0))
            return report(*args)

        with mock.patch.object(checks, "_print_check_report", side_effect=verify_ledger):
            result, document = self.run_json()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        self.assertEqual(result.stderr.splitlines()[-1], "check: passed (3 checks)")

    def test_rejected_verdict_is_last_in_the_merged_log(self):
        config = _policy_with(("smoke", "reject", "skipped"), [
            _command_block("reject", "raise SystemExit(1)"),
            _ledger_command_block("skipped", "raise SystemExit(9)", "{files}"),
        ])
        self.write_config(config.replace("code = true", "code = false").replace('"*.py", ', "", 1))
        self.commit_all()
        for args in ((), ("--json",)):
            with self.subTest(args=args):
                log = self.merged_check("--base", "HEAD", *args, status=1)
                self.assertIn("check: skipped: not run", log)
                self.assertEqual(log.splitlines()[-1], "check: failed (reject)")
                record = self.read_ledger(log)
                self.assert_ids(record, self.expected_ids())
                self.assertEqual((record["decision"], record["exit_status"]), ("rejected", 1))

    def test_unterminated_tool_output_still_leaves_one_parseable_record(self):
        self.write_config(_policy_with(("smoke", "diagnostic"), [
            _command_block(
                "diagnostic", "import sys; sys.stderr.write('fixture diagnostic'); sys.exit(1)",
            ),
        ]))
        log = self.merged_check(status=1)
        self.assertIn("fixture diagnostic", log)
        record = self.read_ledger(log)
        self.assert_ids(record, self.expected_ids())
        self.assertNotIn("fixture diagnostic", json.dumps(record))

    def test_failed_ledger_write_preserves_an_unwind(self):
        error = policy.GateError("original check error")
        self.ledger_path.mkdir()
        with mock.patch.object(checks, "run_check", side_effect=error):
            result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["error"], str(error))
        message, = error.__notes__
        self.assertIn(f"check: cannot write the gate ledger to {self.ledger_path}:", message)
        self.assertIn(os.strerror(errno.EISDIR), message)
        self.assertEqual(result.stderr.splitlines()[-1], message)


    def test_authorized_trusted_run_uses_the_candidate_policy_digest(self):
        self.add_file("tools.lock.toml", "")
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        candidate = BASE_CONFIG + "\n# authorized policy bytes\n"
        self.write_config(candidate)
        result, document = self.run_json(
            "--policy-from", str(trusted), "--allow-protected", "quality-gate.toml",
        )
        record = self.assert_json_ledger(result, document)
        self.assertEqual(document["schema"], 4)
        self.assertEqual(document["decision"], "accepted")
        self.assertEqual(record["policy_sha256"], hashlib.sha256(candidate.encode()).hexdigest())

    def test_no_flag_ignores_former_destination_and_takes_one_sample(self):
        former = self.repo / ".git" / "qg-ledger.jsonl"
        former.mkdir()
        identity = gate_result.consumer_identity
        with (
            mock.patch.object(gate_result, "consumer_identity", wraps=identity) as sample,
            mock.patch.object(gate_result, "append_ledger") as append,
            mock.patch.object(self, "gate_arguments", super().gate_arguments),
        ):
            result, document = self.run_json()
        self.assertEqual(
            (result.returncode, document["decision"], result.stderr.splitlines()[-1]),
            (0, "accepted", "check: passed (3 checks)"), output(result),
        )
        sample.assert_called_once_with(self.repo)
        append.assert_not_called()
        self.assertTrue(former.is_dir())

    def test_git_inspections_preserve_index_bytes_after_a_tracked_mtime_change(self):
        self.commit_all()
        tracked = self.repo / "a.py"
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns - 10_000_000_000))
        git_dir = self.repo / ".git"

        def snapshot():
            return {str(path.relative_to(git_dir)): None if path.is_dir() else path.read_bytes()
                    for path in git_dir.rglob("*")}

        before = snapshot()
        with (
            mock.patch.object(files, "run", wraps=files.run) as file_probes,
            mock.patch.object(gate_result, "run", wraps=gate_result.run) as result_probes,
            mock.patch.object(self, "gate_arguments", super().gate_arguments),
        ):
            result, document = self.run_json()
        self.assertEqual((result.returncode, document["decision"]), (0, "accepted"), output(result))
        self.assertIs(document["dirty"], False)
        self.assertEqual(snapshot(), before)
        calls = [entry.args[0] for probe in (file_probes, result_probes) for entry in probe.call_args_list]
        self.assertTrue(calls)
        for argv in calls:
            self.assertEqual(argv[:2], ["git", "--no-optional-locks"], argv)
            self.assertNotIn("--absolute-git-dir", argv)
        for check in document["checks"][:2]:
            argv = check["diagnostics"]["argv"]
            if argv is not None:
                self.assertIn(argv, calls)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assertNotEqual((git_dir / "index").read_bytes(), before["index"], "fixture must force a refresh")

    def test_configured_and_builtin_rows_follow_fixture_order(self):
        text = _policy_with(("smoke", "later", "last", "outside", "comments"), [
            _chain_block("later", "smoke"), _chain_block("last", "later"),
            _command_block("outside", "raise SystemExit(1)"),
            '[checks.comments]\nadapter = "comments"\ntier = 1\nenforcement = "enforced"',
        ]) + self.module_policy
        self.write_config(text)
        self.commit_all()
        self.add_file("a.py", "print('a')\n# private fixture marker\n")
        with mock.patch.dict(adapters.ADAPTERS, {CHAIN_STUB.name: CHAIN_STUB}):
            result, document = self.run_json("--base", "HEAD", "--only", "last", "comments")
        record = self.read_ledger(result.stdout, result.stderr)
        expected_order = ["inventory", "hygiene", "module-contracts", "smoke", "later", "last", "comments"]
        self.assert_ids(record, set(expected_order))
        self.assertEqual([row["id"] for row in record["checks"]], expected_order)
        self.assertEqual(result.returncode, 1, output(result))
        self.assert_json_evidence(result, document, record)
        self.assertEqual(record["scope"], "affected")
        self.assertEqual(record["selected"], ["smoke", "later", "last", "comments"])
        self.assertEqual(record["base"], document["base"])
        self.assertEqual(record["changed_paths"], document["changed_paths"])
        self.assertEqual(record["changed_paths"], ["a.py"])
        self.assertEqual(record["resolved_base"], self.git("rev-parse", "HEAD").stdout.strip())
        self.assertEqual(record["policy_sha256"], hashlib.sha256(text.encode()).hexdigest())
        expected_fields = {
            "id", "adapter", "metric_version", "execution", "outcome", "duration_seconds", "satisfied",
            "enforcement", "location_coverage", "resolved_baseline_entries", "unmeasured_baseline_entries",
            "resolved_base", "selection", "findings",
        }
        for row, rendered in zip(record["checks"], document["checks"], strict=True):
            with self.subTest(check=row["id"]):
                self.assertCountEqual(row, expected_fields, "missing or extra evidence fields")
                for field in ("resolved_baseline_entries", "unmeasured_baseline_entries"):
                    self.assertEqual(row[field], rendered[field], field)
                if row["id"] == "comments":
                    source, = rendered["measurement"]["findings"]
                    self.assertEqual(row["findings"], [{"locations": [{
                        "path": source["path"], "start_line": source["line"], "end_line": source["line"],
                    }]}])
                else:
                    self.assertEqual(row["findings"], rendered["findings"])
        finding, = self.check_by_id(record, "comments")["findings"]
        self.assertEqual(finding, {"locations": [{"path": "a.py", "start_line": 2, "end_line": 2}]})
        self.assertNotIn("private fixture marker", json.dumps(record))

    def test_shared_override_is_taken_from_the_scheduler(self):
        self.write_config(BASE_CONFIG + self.module_policy)
        self.commit_all()
        head = self.git("rev-parse", "HEAD").stdout.strip()
        result, document = self.run_json(env={"QG_DIFF_BASE": "HEAD"})
        record = self.assert_json_ledger(result, document)
        self.assertIsNone(record["base"])
        self.assertIsNone(record["changed_paths"])
        self.assertEqual(record["resolved_base"], head)
        self.assertEqual(self.check_by_id(record, "module-contracts")["resolved_base"], head)

    def test_dispatch_unwind_preserves_the_observed_prefix(self):
        self.write_config(_policy_with(("smoke", "abort", "later"), [
            _command_block("abort", "pass"), _command_block("later", "pass"),
        ]))
        observed = []
        execute = checks._run_selected_check

        def interrupt(root, config, check, *args):
            observed.append(check.id)
            if len(observed) == 2:
                raise policy.GateError("active dispatch")
            return execute(root, config, check, *args)

        with mock.patch.object(checks, "_run_selected_check", side_effect=interrupt):
            result, document = self.run_json()
        record = self.read_ledger(result.stdout, result.stderr)
        self.assertEqual(document["error"], "active dispatch")
        self.assertEqual(observed, ["smoke", "abort"])
        prefix, active = record["checks"][:-1], record["checks"][-1]
        self.assertEqual([row["id"] for row in prefix], ["inventory", "hygiene", *observed[:-1]])
        self.assertEqual([row["execution"] for row in prefix], ["completed"] * len(prefix))
        self.assertEqual(active["id"], observed[-1])
        self.assertEqual(active["execution"], "interrupted")
        self.assertIsNone(active["outcome"])
        self.assertIsNone(active["satisfied"])
        self.assertEqual(active["termination"], "GateError")
        self.assertNotIn("later", {row["id"] for row in record["checks"]})

    def test_trust_drift_is_finalized_before_ordered_publication(self):
        policy_path = self.repo / "quality-gate.toml"
        self.add_file("tools.lock.toml", "")
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        decoded = policy_path.read_bytes()
        original = checks._run_selected_check

        def edit_policy(*args, **kwargs):
            policy_path.write_bytes(decoded + b"\n# drift\n")
            return original(*args, **kwargs)

        class OrderedStream(io.StringIO):
            def write(self, value):
                observations.append((self, "write", value))
                return super().write(value)

            def flush(self):
                observations.append((self, "flush", None))
                return super().flush()

        observations = []
        stdout, stderr = OrderedStream(), OrderedStream()
        append = gate_result.append_ledger

        def observe_append(*args):
            observations.append((None, "append", args[-1]))
            append(*args)

        argv = self.gate_arguments(("check", "--json", "--policy-from", str(trusted)), None, True)
        with (
            mock.patch.dict(os.environ, self.env(), clear=True),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.object(checks, "_run_selected_check", side_effect=edit_policy),
            mock.patch.object(gate_result, "append_ledger", side_effect=observe_append),
        ):
            status = cli.main(argv)
        self.assertEqual(status, 2, stderr.getvalue())
        document = json.loads(stdout.getvalue())
        record = self.read_ledger(stdout.getvalue(), stderr.getvalue())
        self.assertEqual(document["schema"], 4)
        self.assertEqual(document["decision"], "error")
        self.assertEqual(record["decision"], "error")
        self.assertEqual(record["exit_status"], status)
        self.assertEqual(record["policy_sha256"], hashlib.sha256(decoded).hexdigest())
        self.assertTrue(record["complete"])
        self.assertIsNone(record["termination"])
        append_index = next(i for i, (_, action, _) in enumerate(observations) if action == "append")
        tail = observations[append_index + 1:]
        self.assertEqual(tail[:3], [(stdout, "flush", None), (stderr, "flush", None),
                                   (stdout, "write", json.dumps(document, indent=2))])
        self.assertTrue(stderr.getvalue().splitlines()[-1].startswith("check: error:"))
        self.assertNotIn("check: passed", stderr.getvalue())


class LedgerBoundaryTests(FixtureCase):
    def test_preflight_never_calls_writer(self):
        path = self.base / "evidence.jsonl"
        with mock.patch.object(gate_result, "append_ledger", create=True) as append:
            for previous in (None, b'{"schema":1}\n'):
                if previous is not None:
                    path.write_bytes(previous)
                for options in (("--only", "missing"), ("--base", "missing"), ("--prune", "missing")):
                    result, document = self.run_json("--ledger", str(path), *options)
                    self.assertEqual(result.returncode, 2, output(result))
                    self.assertIn("missing", document["error"])
                    self.assertNotIn("unrecognized arguments", document["error"])
                    append.assert_not_called()
                    self.assertEqual(path.read_bytes() if path.exists() else None, previous)

    def test_refused_first_publication_leaves_destination_absent(self):
        path = self.base / "evidence.jsonl"
        error = PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        with mock.patch.object(os, "link", side_effect=error) as publish:
            result, document = self.run_json("--ledger", "../evidence.jsonl")
        publish.assert_called_once()
        self.assertFalse(path.exists())
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("../evidence.jsonl", document["error"])
        self.assertIn(os.strerror(errno.EACCES), document["error"])
        self.assertNotIn("check: passed", result.stderr)

    def test_short_write_leaves_partial_tail_and_later_appends_refuse_it(self):
        path = self.base / "evidence.jsonl"
        args = ("--ledger", str(path))
        before, _ = self.run_json(*args)
        self.assertEqual(before.returncode, 0, output(before))
        original = path.read_bytes()
        write = os.write

        def short_write(fd, data):
            return write(fd, data[:5])

        with mock.patch.object(gate_result.os, "write", side_effect=short_write):
            result, document = self.run_json(*args)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("short ledger write", document["error"])
        self.assertIn(str(path), document["error"])
        self.assertNotIn("check: passed", result.stderr)
        self.assertEqual(path.read_bytes(), original + b'{"sch')
        result, document = self.run_json(*args)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("incomplete record", document["error"])
        self.assertEqual(path.read_bytes(), original + b'{"sch')

    def test_first_record_race_appends_to_the_destination_published_by_another_writer(self):
        path = self.base / "evidence.jsonl"
        first = b'{"schema":1,"run_id":"another"}\n'
        link = os.link

        def publish_after_another_writer(source, destination):
            path.write_bytes(first)
            link(source, destination)

        with mock.patch.object(os, "link", side_effect=publish_after_another_writer):
            result, document = self.run_json("--ledger", str(path))
        self.assertEqual(result.returncode, 0, output(result))
        previous, appended = path.read_bytes().splitlines(keepends=True)
        self.assertEqual(previous, first)
        self.assertEqual(json.loads(appended)["decision"], document["decision"])

    def test_unhandled_unwind_keeps_a_null_status(self):
        path = self.base / "evidence.jsonl"
        config = policy.load_config(self.repo)
        error = RuntimeError("unhandled dispatch")
        with (
            mock.patch.object(checks, "run_check", side_effect=error),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(RuntimeError) as raised,
        ):
            checks.command_check(self.repo, config, ledger_path=str(path))
        self.assertIs(raised.exception, error)
        line, = path.read_bytes().splitlines()
        record = json.loads(line)
        self.assertIsNone(record["exit_status"])
        self.assertEqual(record["termination"], "RuntimeError")
        self.assertFalse(record["complete"])

    def test_invalid_path_objects_and_missing_parents_are_refused(self):
        link = self.base / "dangling"
        missing = self.base / "target"
        link.symlink_to(missing)
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        absent = self.base / "absent" / "ledger"
        for path in (link, fifo, absent):
            with self.subTest(path=path):
                result, document = self.run_json("--ledger", str(path))
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(str(path), document["error"])
                self.assertNotIn("check: passed", result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertFalse(missing.exists())
        self.assertTrue(fifo.is_fifo())
        self.assertFalse(absent.parent.exists())

    def test_relative_destination_uses_invocation_directory(self):
        cwd = self.base / "invocation"
        cwd.mkdir()
        result = self.run_qg("check", "--json", "--ledger", "evidence.jsonl", cwd=cwd, repo=self.repo)
        document = self.parse_json(result)
        self.assertEqual(result.returncode, 0, output(result))
        lines = (cwd / "evidence.jsonl").read_bytes().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["decision"], document["decision"])
        self.assertFalse((self.repo / "evidence.jsonl").exists())

    def test_builtin_error_argv_comes_from_the_failed_probe(self):
        run = files.run
        failed = []

        def refuse_deleted(argv, **kwargs):
            if "--deleted" in argv:
                failed.append(argv)
                return runner.RunResult(tuple(argv), "completed", 1, stderr=b"fixture git refusal")
            return run(argv, **kwargs)

        with mock.patch.object(files, "run", side_effect=refuse_deleted):
            result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(len(failed), 2)
        for identifier, argv in zip(("inventory", "hygiene"), failed, strict=True):
            check = self.check_by_id(document, identifier)
            self.assertEqual(check["diagnostics"]["argv"], argv)
            self.assertEqual(argv[1], "--no-optional-locks")


class FailureCauseTests(FixtureCase):
    """A rejected check names its root failures and reports consequences apart."""

    def add_passing_test(self) -> None:
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
        )

    def add_failing_test(self) -> None:
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            "    def test_bad(self):\n"
            "        self.assertTrue(False)\n",
        )

    def run_with_test_chain(self):
        with mock.patch.dict(
            adapters.ADAPTERS, {TEST_CHAIN_STUB.name: TEST_CHAIN_STUB}
        ):
            return self.run_json()

    def crap_setup(self) -> None:
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text([], check="crap", metric_version="python-lines/1"),
        )
        self.write_config(crap_config())

    def add_crap_failure(self) -> None:
        self.add_file(
            "pkg/three.py",
            "def three(value):\n"
            "    if value:\n"
            "        if value > 1:\n"
            "            return 1\n"
            "    return 2\n",
        )

    def test_a_failing_suite_reports_only_itself_and_crap_as_its_consequence(
        self,
    ) -> None:
        self.crap_setup()
        self.add_failing_test()
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn("check: failed (tests)\n", result.stderr)
        self.assertIn(
            "check: consequences (crap because tests; "
            "obligation python tier 1 because tests; "
            "obligation test tier 1 because tests)\n",
            result.stderr,
        )
        self.assertIsNone(self.check_by_id(document, "tests")["caused_by"])
        self.assertEqual(
            self.check_by_id(document, "crap")["caused_by"], ["tests"]
        )
        obligation = next(
            item for item in document["obligations"]
            if item["class"] == "python"
        )
        self.assertEqual(obligation["status"], "unsatisfied")
        self.assertEqual(obligation["caused_by"], ["tests"])
        self.assertEqual(document["schema"], 3)

    def test_a_failing_crap_with_a_passing_suite_is_a_root(self) -> None:
        self.crap_setup()
        self.add_passing_test()
        self.add_crap_failure()
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn("check: failed (crap)", result.stderr)
        self.assertNotIn("check: consequences", result.stderr)
        self.assertIsNone(self.check_by_id(document, "crap")["caused_by"])
        self.assertIsNone(self.check_by_id(document, "tests")["caused_by"])

    def test_a_two_step_chain_resolves_to_its_root(self) -> None:
        self.write_config(_policy_with(
            ("a", "b", "c"),
            [
                _command_block("a", "raise SystemExit(1)"),
                _chain_block("b", "a"),
                _chain_block("c", "b"),
            ],
        ))
        with mock.patch.dict(
            adapters.ADAPTERS, {CHAIN_STUB.name: CHAIN_STUB}
        ):
            result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn(
            "check: failed (a, obligation python tier 1)\n", result.stderr
        )
        self.assertIn(
            "check: consequences (b because a; c because a)", result.stderr
        )
        self.assertIsNone(self.check_by_id(document, "a")["caused_by"])
        self.assertEqual(self.check_by_id(document, "b")["caused_by"], ["a"])
        self.assertEqual(self.check_by_id(document, "c")["caused_by"], ["a"])

    def test_implicit_verification_dependency_is_a_consequence_of_the_suite(
        self,
    ) -> None:
        self.write_config(_policy_with(
            ("tests", "verification"),
            [
                _tests_command_block("tests", "print('no test summary')"),
                _verification_block("verification.toml"),
            ],
        ))
        self.add_file(
            "verification.toml",
            'check = "verification"\nmetric_version = "verification/1"\n',
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn("check: failed (tests)\n", result.stderr)
        self.assertIn(
            "check: consequences (verification because tests; "
            "obligation python tier 1 because tests)\n",
            result.stderr,
        )
        self.assertNotIn("check: failed (tests, verification)", result.stderr)
        self.assertEqual(
            self.check_by_id(document, "verification")["caused_by"], ["tests"]
        )
        obligation = next(
            item for item in document["obligations"]
            if item["class"] == "python"
        )
        self.assertEqual(obligation["caused_by"], ["tests"])

    def test_an_obligation_whose_candidate_is_a_consequence_names_the_root(
        self,
    ) -> None:
        self.write_config(_policy_with(
            ("root", "dependent"),
            [
                _command_block("root", "raise SystemExit(1)"),
                _test_chain_block("dependent", "root"),
            ],
        ))
        result, document = self.run_with_test_chain()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn("check: failed (root)\n", result.stderr)
        self.assertIn(
            "check: consequences (dependent because root; "
            "obligation python tier 1 because root)\n",
            result.stderr,
        )
        self.assertEqual(
            self.check_by_id(document, "dependent")["caused_by"], ["root"]
        )
        obligation = next(
            item for item in document["obligations"]
            if item["class"] == "python"
        )
        self.assertEqual(obligation["caused_by"], ["root"])

    def test_an_obligation_with_a_satisfied_candidate_is_a_root(self) -> None:
        self.write_config(_policy_with(
            ("zero", "failed"),
            [
                _tests_command_block(
                    "zero", "print('Ran 0 tests in 0.1s')", "advisory"
                ),
                _tests_command_block(
                    "failed", "raise SystemExit(1)"
                ),
            ],
        ))
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn(
            "check: failed (failed, obligation python tier 1)\n",
            result.stderr,
        )
        self.assertNotIn("obligation python tier 1 because", result.stderr)
        obligation = next(
            item for item in document["obligations"]
            if item["class"] == "python"
        )
        self.assertIsNone(obligation["caused_by"])

    def test_a_check_with_two_roots_keeps_policy_order(self) -> None:
        self.write_config(_policy_with(
            ("z", "a", "verification"),
            [
                _tests_command_block("z", "raise SystemExit(1)"),
                _tests_command_block("a", "raise SystemExit(1)"),
                _verification_block("verification.toml"),
            ],
        ))
        self.add_file(
            "verification.toml",
            'check = "verification"\nmetric_version = "verification/1"\n',
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(
            "check: consequences (verification because z, a; "
            "obligation python tier 1 because z, a)\n",
            result.stderr,
        )
        self.assertEqual(
            self.check_by_id(document, "verification")["caused_by"],
            ["z", "a"],
        )

    def test_an_obligation_lists_its_causes_in_policy_order(self) -> None:
        self.write_config(_policy_with(
            ("c", "b", "a", "d"),
            [
                _tests_command_block("a", "raise SystemExit(1)"),
                _test_chain_block("b", "a"),
                _command_block("d", "raise SystemExit(1)"),
                _test_chain_block("c", "d"),
            ],
        ))
        result, document = self.run_with_test_chain()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("check: failed (a, d)\n", result.stderr)
        self.assertIn(
            "check: consequences (b because a; c because d; "
            "obligation python tier 1 because a, d)\n",
            result.stderr,
        )
        obligations = [
            item for item in document["obligations"]
            if item["class"] == "python"
        ]
        self.assertEqual(len(obligations), 1)
        self.assertEqual(obligations[0]["caused_by"], ["a", "d"])

    def test_multiple_roots_are_deduplicated_in_summary_order(self) -> None:
        self.write_config(_policy_with(
            ("a", "b", "d", "c", "verification"),
            [
                _tests_command_block("a", "raise SystemExit(1)"),
                _test_chain_block("b", "a"),
                _command_block("d", "raise SystemExit(1)"),
                _test_chain_block("c", "d"),
                _verification_block("verification.toml"),
            ],
        ))
        self.add_file(
            "verification.toml",
            'check = "verification"\nmetric_version = "verification/1"\n',
        )
        result, document = self.run_with_test_chain()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn("check: failed (a, d)\n", result.stderr)
        self.assertIn(
            "check: consequences (b because a; c because d; "
            "verification because a, d; "
            "obligation python tier 1 because a, d)\n",
            result.stderr,
        )
        self.assertEqual(self.check_by_id(document, "b")["caused_by"], ["a"])
        self.assertEqual(self.check_by_id(document, "c")["caused_by"], ["d"])
        self.assertEqual(
            self.check_by_id(document, "verification")["caused_by"],
            ["a", "d"],
        )
        obligation = next(
            item for item in document["obligations"]
            if item["class"] == "python"
        )
        self.assertEqual(obligation["caused_by"], ["a", "d"])


if __name__ == "__main__":
    unittest.main()
