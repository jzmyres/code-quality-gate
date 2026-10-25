"""Unit tests for the generic ratchet's numeric and baseline decisions."""
from __future__ import annotations

import contextlib
import datetime
import importlib
import io
import sys
import unittest

from support import GATE

sys.path.insert(0, str(GATE))
ratchet = importlib.import_module("quality_gate.ratchet")
policy = importlib.import_module("quality_gate.policy")


class RatchetTests(unittest.TestCase):
    def decide(
        self,
        findings: list[tuple[str, float]],
        entries: list[tuple[str, float, str, object]],
        *,
        threshold: float = 0,
    ):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = ratchet.evaluate(
                [ratchet.Finding(*item, "file:1") for item in findings],
                [
                    ratchet.BaselineEntry(
                        subject,
                        bound,
                        reason,
                        expires if isinstance(expires, datetime.date) else None,
                    )
                    for subject, bound, reason, expires in entries
                ],
                threshold=threshold,
                enforcement="enforced",
                prefix="check: metric",
                adapter="metric",
            )
        return result, output.getvalue(), errors.getvalue()

    def test_subject_above_threshold_without_baseline_fails(self) -> None:
        result, _out, errors = self.decide([("new", 1)], [])
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.findings[0].blocking)
        self.assertIn("new", errors)
        self.assertIn("threshold 0", errors)
        self.assertIn("file:1", errors)

    def test_exactly_at_bound_passes(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 5.0)], [("subject", 5.0, "accepted", None)]
        )
        self.assertEqual(result.outcome, "pass")
        self.assertTrue(result.exceptions)

    def test_one_tenth_above_bound_fails(self) -> None:
        result, _out, errors = self.decide(
            [("subject", 5.1)], [("subject", 5.0, "accepted", None)]
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("5.1", errors)
        self.assertIn("bound 5", errors)

    def test_empty_reason_fails_even_when_covered(self) -> None:
        result, _out, errors = self.decide(
            [("subject", 1)], [("subject", 10, "   ", None)]
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("empty reason", errors)

    def test_expired_entry_no_longer_covers(self) -> None:
        result, stdout, errors = self.decide(
            [("subject", 1)],
            [("subject", 10, "old", datetime.date(2000, 1, 1))],
        )
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.findings[0].expired)
        self.assertIn("expired baseline entry", stdout + errors)
        self.assertIn("2000-01-01", stdout + errors)

    def test_unexpired_entry_covers(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 1)],
            [("subject", 10, "accepted", datetime.date(2999, 1, 1))],
        )
        self.assertEqual(result.outcome, "pass")

    def test_entry_below_threshold_is_resolved(self) -> None:
        result, stdout, _errors = self.decide(
            [("subject", 5)],
            [("subject", 10, "old", None)],
            threshold=6,
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.resolved, ["subject"])
        self.assertFalse(result.exceptions)
        self.assertIn("resolved subject", stdout)

    def test_unmeasured_entry_is_resolved(self) -> None:
        result, stdout, _errors = self.decide(
            [], [("gone", 4, "old", None)]
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.resolved, ["gone"])
        self.assertIn("resolved gone", stdout)

    def test_baseline_exception_is_reported(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 2)], [("subject", 2, "accepted", None)]
        )
        self.assertEqual(result.outcome, "pass")
        self.assertTrue(result.exceptions)

    def test_prune_lowers_but_never_raises(self) -> None:
        result, _out, _errors = self.decide(
            [("lower", 1), ("same", 3)],
            [
                ("lower", 5, "accepted", None),
                ("same", 3, "accepted", None),
            ],
        )
        pruned = ratchet.pruned_entries(result)
        self.assertEqual([entry.bound for entry in pruned], [1, 3])

    def test_prune_drops_resolved_entries(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 5)],
            [
                ("subject", 10, "old", None),
                ("gone", 2, "gone", None),
            ],
            threshold=6,
        )
        self.assertEqual(ratchet.pruned_entries(result), [])

    def test_prune_refuses_while_the_check_fails(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 6)], [("subject", 5, "accepted", None)]
        )
        self.assertEqual(result.outcome, "fail")
        with self.assertRaises(policy.GateError):
            ratchet.pruned_entries(result)


if __name__ == "__main__":
    unittest.main()
