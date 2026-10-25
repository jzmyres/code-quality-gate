"""Unit tests for the generic ratchet's numeric and baseline decisions."""
from __future__ import annotations

import contextlib
import datetime
import importlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

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
        domain=None,
        today: datetime.date | None = None,
        direction: str = "max",
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
                domain=domain or ratchet.Domain.all(),
                today=today,
                direction=direction,
            )
        return result, output.getvalue(), errors.getvalue()

    def test_subject_above_threshold_without_baseline_fails(self) -> None:
        result, _out, errors = self.decide([("new", 1)], [])
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.findings[0].blocking)
        self.assertIn("new", errors)
        self.assertIn("threshold 0", errors)
        self.assertIn("file:1", errors)

    def test_exactly_at_bound_passes_through_the_baseline(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 5.0)], [("subject", 5.0, "accepted", None)]
        )
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.satisfied)
        self.assertTrue(result.exceptions)
        self.assertTrue(result.findings[0].covered_by_baseline)
        self.assertFalse(result.findings[0].blocking)

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
        self.assertFalse(result.satisfied)
        self.assertTrue(result.findings[0].expired)
        self.assertIn("expired baseline entry", stdout + errors)
        self.assertIn("2000-01-01", stdout + errors)

    def test_unexpired_entry_covers(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 1)],
            [("subject", 10, "accepted", datetime.date(2999, 1, 1))],
        )
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.satisfied)

    def test_entry_expiring_today_still_covers(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 1)],
            [("subject", 10, "accepted", datetime.date(2026, 10, 25))],
            today=datetime.date(2026, 10, 25),
        )
        self.assertTrue(result.satisfied)
        self.assertFalse(result.findings[0].expired)

    def test_entry_expired_yesterday_does_not_cover(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 1)],
            [("subject", 10, "accepted", datetime.date(2026, 10, 24))],
            today=datetime.date(2026, 10, 25),
        )
        self.assertFalse(result.satisfied)
        self.assertTrue(result.findings[0].expired)

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

    def test_unmeasured_entry_is_resolved_only_inside_the_domain(self) -> None:
        result, stdout, _errors = self.decide(
            [], [("gone", 4, "old", None)]
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.resolved, ["gone"])
        self.assertIn("resolved gone", stdout)

    def test_file_domain_splits_subjects_at_their_last_colon(self) -> None:
        domain = ratchet.Domain.of_files(("pkg/a:b.py",))
        self.assertTrue(domain.contains("pkg/a:b.py:f"))
        self.assertFalse(domain.contains("pkg/a.py:f"))

    def test_subject_domain_lists_explicit_subjects(self) -> None:
        domain = ratchet.Domain.of_subjects(("one",))
        self.assertTrue(domain.contains("one"))
        self.assertFalse(domain.contains("two"))

    def test_entry_outside_the_measured_domain_stays_unmeasured(self) -> None:
        result, stdout, _errors = self.decide(
            [],
            [("other.py:gone", 4, "old", None)],
            domain=ratchet.Domain.of_files(("a.py",)),
        )
        self.assertEqual(result.outcome, "pass")
        self.assertTrue(result.satisfied)
        self.assertEqual(result.resolved, [])
        self.assertEqual(result.unmeasured, ["other.py:gone"])
        self.assertIn("unmeasured other.py:gone", stdout)
        self.assertEqual(
            [entry.subject for entry in ratchet.pruned_entries(result)],
            ["other.py:gone"],
        )

    def test_baseline_exception_is_reported(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 2)], [("subject", 2, "accepted", None)]
        )
        self.assertEqual(result.outcome, "fail")
        self.assertTrue(result.satisfied)
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

    def test_min_metric_passes_at_or_above_its_floor(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 5.0)],
            [("subject", 5.0, "floor", None)],
            direction="min",
        )
        self.assertEqual(result.outcome, "pass")
        self.assertTrue(result.satisfied)
        self.assertFalse(result.exceptions)

    def test_min_metric_below_its_floor_fails(self) -> None:
        result, _out, errors = self.decide(
            [("subject", 4.0)],
            [("subject", 5.0, "floor", None)],
            direction="min",
        )
        self.assertEqual(result.outcome, "fail")
        self.assertFalse(result.satisfied)
        self.assertIn("falls below baseline bound 5", errors)
        self.assertIn("file:1", errors)

    def test_min_metric_without_a_baseline_entry_is_unmeasured(self) -> None:
        result, _out, errors = self.decide(
            [("subject", 5.0)], [], direction="min"
        )
        self.assertEqual(result.outcome, "fail")
        self.assertFalse(result.satisfied)
        self.assertEqual(result.unmeasured, ["subject"])
        self.assertEqual(
            result.findings[0].error,
            "unmeasured: no baseline entry for a min metric",
        )
        self.assertIn("unmeasured: no baseline entry", errors)

    def test_prune_raises_a_min_floor_but_never_lowers_it(self) -> None:
        result, _out, _errors = self.decide(
            [("raise", 7), ("same", 3)],
            [
                ("raise", 5, "floor", None),
                ("same", 3, "floor", None),
            ],
            direction="min",
        )
        pruned = ratchet.pruned_entries(result)
        self.assertEqual([entry.bound for entry in pruned], [7, 3])

    def test_non_finite_measured_value_is_unsupported(self) -> None:
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(policy.UnsupportedError):
                    self.decide([("subject", value)], [])

    def test_non_finite_baseline_bound_is_unsupported(self) -> None:
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(policy.UnsupportedError):
                    self.decide(
                        [("subject", 1)],
                        [("subject", value, "accepted", None)],
                    )


class BaselineFileTests(unittest.TestCase):
    def test_toml_value_covers_scalar_types(self) -> None:
        self.assertEqual(ratchet._toml_value(True), "true")
        self.assertEqual(ratchet._toml_value(False), "false")
        self.assertEqual(ratchet._toml_value(2), "2")
        self.assertEqual(ratchet._toml_value(2.5), "2.5")
        self.assertEqual(
            ratchet._toml_value(datetime.datetime(2026, 1, 2, 3, 4, 5)),
            "2026-01-02T03:04:05",
        )
        self.assertEqual(
            ratchet._toml_value(datetime.date(2026, 1, 2)), "2026-01-02"
        )
        self.assertEqual(
            ratchet._toml_value("a\n"), json.dumps("a\n", ensure_ascii=False)
        )
        self.assertEqual(ratchet._toml_value(["a", "b"]), '["a", "b"]')

    def test_toml_value_rejects_non_finite_and_unknown_values(self) -> None:
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(policy.GateError):
                    ratchet._toml_value(value)
        with self.assertRaises(policy.GateError):
            ratchet._toml_value(object())

    def test_write_and_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.toml"
            ratchet.write_baseline(
                path,
                [
                    ratchet.BaselineEntry(
                        "subject",
                        2,
                        "reason",
                        datetime.date(2999, 1, 1),
                        {"files": ["a.py", "b.py"]},
                    )
                ],
                check_id="metric",
                metric_version="metric/1",
            )
            entries = ratchet.load_baseline(
                path,
                check_id="metric",
                metric_version="metric/1",
                allowed_extras=("files",),
            )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].subject, "subject")
        self.assertEqual(entries[0].expires, datetime.date(2999, 1, 1))
        self.assertEqual(entries[0].extras["files"], ["a.py", "b.py"])

    def test_header_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.toml"
            path.write_text(
                'check = "other"\nmetric_version = "metric/1"\n',
                encoding="utf-8",
            )
            with self.assertRaises(policy.GateError) as raised:
                ratchet.load_baseline(
                    path, check_id="metric", metric_version="metric/1"
                )
        self.assertIn("check", str(raised.exception))

    def test_missing_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.toml"
            path.write_text("[[entry]]\n", encoding="utf-8")
            with self.assertRaises(policy.GateError) as raised:
                ratchet.load_baseline(
                    path, check_id="metric", metric_version="metric/1"
                )
        self.assertIn("check", str(raised.exception))

    def test_invalid_files_extra_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.toml"
            path.write_text(
                'check = "metric"\nmetric_version = "metric/1"\n'
                '[[entry]]\nsubject = "s"\nbound = 1\n'
                'reason = "r"\nfiles = "not a list"\n',
                encoding="utf-8",
            )
            with self.assertRaises(policy.GateError) as raised:
                ratchet.load_baseline(
                    path,
                    check_id="metric",
                    metric_version="metric/1",
                    allowed_extras=("files",),
                )
        self.assertIn("list of strings", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
