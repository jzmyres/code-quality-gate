"""Unit tests for gate identity failure reporting."""
from __future__ import annotations

import importlib
import sys
import unittest
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
gate_result = importlib.import_module("quality_gate.gate_result")
runner = importlib.import_module("quality_gate.runner")
files = importlib.import_module("quality_gate.files")
ratchet = importlib.import_module("quality_gate.ratchet")


class GitProblemTests(unittest.TestCase):
    def test_no_run_is_unknown(self) -> None:
        self.assertEqual(
            gate_result._git_problem(None, "git failed"),
            "unknown: cannot run git",
        )

    def test_unfinished_execution_names_it(self) -> None:
        result = runner.RunResult(("git",), "budget", None)
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: git budget",
        )

    def test_failed_run_reports_stderr(self) -> None:
        result = runner.RunResult(
            ("git",), "completed", 1, stderr=b"fatal: bad\n"
        )
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: fatal: bad",
        )

    def test_failed_run_without_stderr_uses_the_context(self) -> None:
        result = runner.RunResult(("git",), "completed", 1)
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: git failed",
        )

    def test_successful_run_has_no_problem(self) -> None:
        result = runner.RunResult(("git",), "completed", 0)
        self.assertIsNone(
            gate_result._git_problem(result, "git failed")
        )


class StrictEndpointTests(unittest.TestCase):
    def test_clean_status_requires_a_readable_index_without_hiding_flags(self) -> None:
        head = "a" * 40
        status = runner.RunResult(("git",), "completed", 0)
        cases = (
            (b"H ordinary\0", False), (b"h assumed\0", None), (b"S sparse\0", None),
            (b"s sparse-assumed\0", None), (None, None),
        )
        for entries, expected in cases:
            with self.subTest(entries=entries):
                index = (
                    None if entries is None else runner.RunResult(("git",), "completed", 0, stdout=entries)
                )
                with (
                    mock.patch.object(gate_result, "_verified_commit", return_value=(head, "")) as commit,
                    mock.patch.object(gate_result, "_git", side_effect=(status, index)) as probe,
                ):
                    result = gate_result.consumer_identity(GATE, strict=True)
                self.assertEqual(result, {"revision": head, "dirty": expected})
                commit.assert_called_once_with(GATE, "HEAD")
                self.assertEqual(probe.call_args_list, [
                    mock.call(GATE, [
                        "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none",
                    ]),
                    mock.call(GATE, ["ls-files", "-v", "-z"]),
                ])

    def test_visible_changes_take_precedence_over_index_uncertainty(self) -> None:
        status = runner.RunResult(("git",), "completed", 0, stdout=b" M visible\n")
        with (
            mock.patch.object(gate_result, "_verified_commit", return_value=(None, "unknown commit")),
            mock.patch.object(gate_result, "_git", return_value=status) as probe,
        ):
            result = gate_result.consumer_identity(GATE, strict=True)
        self.assertEqual(result, {"revision": None, "dirty": True})
        probe.assert_called_once()


class LedgerProjectionTests(unittest.TestCase):
    def test_unwind_record_keeps_unknown_scope_details_and_active_dispatch(self) -> None:
        endpoint = {"revision": "a" * 40, "dirty": None}
        active = {"id": "inventory", "execution": "interrupted", "termination": "RuntimeError"}
        record = gate_result.ledger_record(
            run_id="fixture", start=endpoint, end=endpoint, version="gate", digest="digest",
            selected=None, base=None, diff=files.DiffBaseOverride(), results=[], interrupted=active,
            document={}, status=None, termination="RuntimeError",
        )
        self.assertEqual(record["checks"], [active])
        self.assertEqual(record["scope"], "full")
        self.assertIsNone(record["attribution_revision"])
        self.assertIsNone(record["exit_status"])
        self.assertFalse(record["complete"])
        self.assertEqual(record["termination"], "RuntimeError")
        self.assertEqual(record["decision"], "error")
        self.assertEqual(record["exemptions"], [])

    def test_structured_finding_evidence_retains_ranges_and_excludes_diagnostics(self) -> None:
        edge = {"source": "a.py", "target": "b.py", "line": 4, "kind": "import", "detail": "hidden"}
        finding = {
            "rule": "module-interface", "edge": edge, "message": "hidden",
            "locations": [{"path": "a.py", "start_line": 4, "end_line": 6, "reason": "hidden"}],
        }
        self.assertEqual(gate_result._ledger_finding(finding), {
            "rule": "module-interface",
            "edge": {"source": "a.py", "target": "b.py", "line": 4, "kind": "import"},
            "locations": [{"path": "a.py", "start_line": 4, "end_line": 6}],
        })
        finding.pop("locations")
        self.assertEqual(
            gate_result._ledger_finding(finding)["locations"],
            [{"path": "a.py", "start_line": 4, "end_line": 4}],
        )

    def test_ratchet_evidence_projects_nested_measurements_and_partial_locations(self) -> None:
        edge = {"source": "a.py", "target": "b.py", "line": 4, "kind": "import"}
        evidence = {
            "cycle": [edge | {"argv": ["secret"]}],
            "edge": edge | {"reason": "secret"},
            "limit": {"max_tokens": 40, "reason": "secret"},
        }
        finding = ratchet.FindingResult(
            subject="tracked subject", value=3, bound=2, threshold=1, baseline_reason="secret",
            blocking=True, location="a.py:4-6", error="secret", measurement=evidence,
        )
        projected = gate_result._ledger_finding(finding)
        self.assertEqual(projected["location"], "a.py:4-6")
        self.assertIsNone(projected["locations"])
        self.assertEqual(projected["measurement"], {
            "cycle": [edge], "edge": edge, "limit": {"max_tokens": 40},
        })
        self.assertTrue(projected["blocking"])
        self.assertNotIn("secret", repr(projected))
        evidence["limit"] = 40
        self.assertEqual(gate_result._ledger_finding(finding)["measurement"]["limit"], 40)


if __name__ == "__main__":
    unittest.main()
