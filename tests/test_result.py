"""Tests for the machine-readable check result and its decision."""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import sys
import unittest
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

sys.path.insert(0, str(GATE))
cli = importlib.import_module("quality_gate.cli")


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
        self.assertEqual(document["schema"], 2)
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
        self.assertIn(
            "obligation python tier 1", result.stderr
        )

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
        self.assertEqual(document["schema"], 2)
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


if __name__ == "__main__":
    unittest.main()
