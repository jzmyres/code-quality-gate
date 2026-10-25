"""Tests for the machine-readable check result and its decision."""
from __future__ import annotations

import hashlib
import unittest

from support import (
    BASE_CONFIG,
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)


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
        ):
            self.assertIn(key, document)
        self.assertEqual(document["schema"], 1)
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
            "tier",
            "enforcement",
            "adapter",
            "metric_version",
            "outcome",
            "duration_seconds",
            "budget_seconds",
            "termination",
            "findings",
            "resolved_baseline_entries",
        ):
            self.assertIn(key, check)
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["termination"], "exit")
        self.assertIsInstance(check["duration_seconds"], float)
        self.assertEqual(check["budget_seconds"], 600)

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
                'run = ["python3", "-c", "pass"]',
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

    def test_advisory_failure_is_accepted_with_exceptions(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'enforcement = "enforced"', 'enforcement = "advisory"'
            ).replace(
                'run = ["python3", "-c", "pass"]',
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
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(len(check["findings"]), 1)
        finding = check["findings"][0]
        for key in (
            "subject",
            "value",
            "bound",
            "threshold",
            "baseline_reason",
            "blocking",
            "location",
        ):
            self.assertIn(key, finding)
        self.assertEqual(finding["subject"], "fp1")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], 1)
        self.assertEqual(finding["threshold"], 0)
        self.assertEqual(finding["baseline_reason"], "deliberate mirror")
        self.assertFalse(finding["blocking"])
        self.assertIn("a.py:1-8", finding["location"])

    def test_policy_error_with_json_is_one_error_document(self) -> None:
        self.write_config(BASE_CONFIG.replace("schema = 1\n", ""))
        result = self.run_qg("check", "--json")
        self.assertEqual(result.returncode, 2, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["decision"], "error")
        self.assertEqual(document["checks"], [])
        self.assertIn("schema", document["error"])
        self.assertIn("schema", result.stderr)

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
