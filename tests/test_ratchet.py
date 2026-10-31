"""Unit tests for the generic ratchet's numeric and baseline decisions."""
from __future__ import annotations

import contextlib
import dataclasses
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
adapters = importlib.import_module("quality_gate.adapters")


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
        adapter: str = "metric",
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
                adapter=adapter,
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

    def test_renamed_clone_descriptor_preserves_failure_wording(self) -> None:
        original = adapters.adapter_for("clones")
        renamed = dataclasses.replace(original, name="repeated-code")
        adapters.register_adapter(renamed)
        self.addCleanup(adapters.remove_adapter, renamed.name)
        expected = (
            "check: metric: new clone added: occurs 2 times, exceeding threshold 0"
            " at file:1\n"
            "check: metric: clone existing: occurs 1 time, exceeding threshold 0"
            " and baseline bound 0 at file:1\n"
            "check: metric: clone expired: occurs 2 times, exceeding threshold 0"
            " (baseline entry expired 2000-01-01) at file:1\n"
        )
        for adapter in (original, original.name, renamed, renamed.name):
            with self.subTest(adapter=adapter):
                result, _out, errors = self.decide(
                    [("added", 2), ("existing", 1), ("expired", 2)],
                    [
                        ("existing", 0, "accepted", None),
                        ("expired", 3, "old", datetime.date(2000, 1, 1)),
                    ],
                    adapter=adapter,
                    today=datetime.date(2026, 10, 30),
                )
                self.assertFalse(result.satisfied)
                self.assertEqual(errors, expected)

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
        self.assertTrue(result.satisfied, "a satisfied ratchet is required before pruning")
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
        self.assertTrue(result.satisfied, "a satisfied ratchet is required before pruning")
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
        self.assertTrue(result.satisfied, "a satisfied ratchet is required before pruning")
        pruned = ratchet.pruned_entries(result)
        self.assertEqual([entry.bound for entry in pruned], [7, 3])

    def test_python_crap_prune_lowers_a_max_bound(self) -> None:
        result, _out, _errors = self.decide(
            [("subject", 1)],
            [("subject", 5, "accepted", None)],
            adapter="python_crap",
        )
        self.assertTrue(result.satisfied)
        self.assertEqual(
            [entry.bound for entry in ratchet.pruned_entries(result)], [1]
        )

    def test_verification_entries_take_their_subject_direction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verification.toml"
            path.write_text(
                'check = "verification"\n'
                'metric_version = "verification/1"\n'
                '[[entry]]\nsubject = "tests:tests:executed"\n'
                'bound = 4\nreason = "floor"\n'
                '[[entry]]\nsubject = "exclusions:a.py:noqa"\n'
                'bound = 2\nreason = "ceiling"\n',
                encoding="utf-8",
            )
            entries = ratchet.load_baseline(
                path,
                check_id="verification",
                metric_version="verification/1",
                adapter="verification",
                direction="max",
            )
        self.assertEqual(
            {entry.subject: entry.direction for entry in entries},
            {"tests:tests:executed": "min", "exclusions:a.py:noqa": "max"},
        )
        result = ratchet.evaluate(
            [
                ratchet.Finding(
                    "tests:tests:executed", 7, "test summary", kind="executed"
                ),
                ratchet.Finding(
                    "exclusions:a.py:noqa", 1, "a.py:1", kind="exclusion"
                ),
            ],
            entries,
            threshold=0,
            enforcement="enforced",
            prefix="check: verification",
            adapter="verification",
            domain=ratchet.Domain.of_files(("a.py",)),
        )
        self.assertTrue(result.satisfied)
        self.assertEqual(
            {entry.subject: entry.bound for entry in ratchet.pruned_entries(result)},
            {"tests:tests:executed": 7, "exclusions:a.py:noqa": 1},
        )

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


class BaselineExtrasTests(unittest.TestCase):
    def load_extras(self, extra_lines: str):
        descriptor = dataclasses.replace(
            adapters.adapter_for("clones"), extras=("tags", "files")
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.toml"
            path.write_text(
                'check = "metric"\nmetric_version = "metric/1"\n'
                '[[entry]]\nsubject = "s"\nbound = 1\nreason = ""\n'
                + extra_lines,
                encoding="utf-8",
            )
            return ratchet.load_baseline(
                path,
                check_id="metric",
                metric_version="metric/1",
                allowed_extras=descriptor.extras,
                adapter=descriptor,
            )

    def empty_reason_errors(self, extra_lines: str) -> str:
        entries = self.load_extras(extra_lines)
        errors = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            result = ratchet.evaluate(
                [], entries, threshold=0, enforcement="enforced",
                prefix="check: metric", adapter="metric", domain=ratchet.Domain.all(),
            )
        self.assertFalse(result.satisfied)
        return errors.getvalue()

    def test_non_files_extra_must_be_a_list(self) -> None:
        with self.assertRaisesRegex(
            policy.GateError, r"entry\[0\]\.tags: expected a list of strings"
        ):
            self.load_extras('files = ["a.py"]\ntags = "not a list"\n')

    def test_non_files_extra_members_must_be_strings(self) -> None:
        with self.assertRaisesRegex(
            policy.GateError, r"entry\[0\]\.tags: expected a list of strings"
        ):
            self.load_extras('files = ["a.py"]\ntags = ["review", 1]\n')

    def test_empty_reason_lists_extras_in_declaration_order(self) -> None:
        errors = self.empty_reason_errors(
            'files = ["a.py", "b.py"]\ntags = ["review", "legacy"]\n'
        )
        self.assertEqual(
            errors,
            "check: metric: baseline entry s: empty reason "
            "(expected a non-empty reason)"
            " (tags: review, legacy) (files: a.py, b.py)\n",
        )

    def test_empty_reason_omits_empty_extra_lists(self) -> None:
        for extra_lines, detail in (
            ('files = ["a.py"]\ntags = []\n', " (files: a.py)"),
            ('files = []\ntags = ["review"]\n', " (tags: review)"),
            ('files = []\ntags = []\n', ""),
        ):
            with self.subTest(extra_lines=extra_lines):
                self.assertEqual(
                    self.empty_reason_errors(extra_lines),
                    "check: metric: baseline entry s: empty reason "
                    f"(expected a non-empty reason){detail}\n",
                )


if __name__ == "__main__":
    unittest.main()
