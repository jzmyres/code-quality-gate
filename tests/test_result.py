"""Tests for the machine-readable check result and its decision."""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import sys
import unittest
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
cli = importlib.import_module("quality_gate.cli")
policy = importlib.import_module("quality_gate.policy")


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
