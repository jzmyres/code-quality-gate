"""Tests for the source-character lint adapter and its ratcheted findings."""
from __future__ import annotations

import unittest
from typing import Any

from support import (
    BASE_CONFIG,
    GATE,
    FixtureCase,
    _add_check_to_class,
    baseline_text,
    output,
)

from quality_gate.files import enumerate_files
from quality_gate.policy import GateError
from quality_gate.source_chars import measure_source_chars


BASELINE = "quality-gate-source-chars.toml"
METRIC_VERSION = "source-chars/1"
ALLOW = '["tab", "lf", "crlf", "form-feed-at-line-start"]'
DENY = '["nul", "bare-cr", "esc", "del", "c1", "bidi"]'


def source_chars_config(*, extra: str = "") -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", "source-chars")
    return text + (
        "\n[checks.source-chars]\n"
        'adapter = "source_chars"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        f'baseline = "{BASELINE}"\n'
        f"{extra}"
    )


def source_chars_baseline(entries: list[dict[str, Any]]) -> str:
    return baseline_text(
        entries, check="source-chars", metric_version=METRIC_VERSION
    )


def character_entry(subject: str, bound: int = 1) -> dict[str, Any]:
    return {
        "subject": subject,
        "bound": bound,
        "reason": "measured source character at adoption",
    }


class MeasurementTests(FixtureCase):
    def findings_for(self, data: bytes) -> list[Any]:
        self.add_file("pkg/mod.py", data)
        return measure_source_chars(self.repo, ["pkg/mod.py"])

    def test_each_rejected_kind_reports_path_line_column_and_codepoint(self) -> None:
        cases = (
            ("nul", b"\x00", "U+0000"),
            ("bare-cr", b"\r", "U+000D"),
            ("esc", b"\x1b", "U+001B"),
            ("del", b"\x7f", "U+007F"),
            ("c1", "\u0085".encode("utf-8"), "U+0085"),
            ("bidi-embedding", "\u202e".encode("utf-8"), "U+202E"),
            ("bidi-isolate", "\u2066".encode("utf-8"), "U+2066"),
            ("other-c0", b"\x07", "U+0007"),
            ("form-feed-not-at-line-start", b"\x0c", "U+000C"),
        )
        for name, marker, label in cases:
            with self.subTest(kind=name):
                findings = self.findings_for(b"first\nab" + marker + b"cd\n")
                self.assertEqual(len(findings), 1, findings)
                finding = findings[0]
                self.assertEqual(finding.subject, f"pkg/mod.py:{label}")
                self.assertEqual(finding.value, 1)
                self.assertEqual(finding.location, "pkg/mod.py:2:3")
                self.assertEqual(
                    finding.measurement,
                    {
                        "path": "pkg/mod.py",
                        "line": 2,
                        "column": 3,
                        "codepoint": label,
                        "occurrences": [
                            {
                                "path": "pkg/mod.py",
                                "line": 2,
                                "column": 3,
                                "codepoint": label,
                            }
                        ],
                    },
                )
                self.assertEqual(finding.locations[0].path, "pkg/mod.py")
                self.assertEqual(finding.locations[0].start_line, 2)

    def test_repeated_code_points_are_one_counted_finding(self) -> None:
        findings = self.findings_for(b"\x00a\x00\n")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.value, 2)
        self.assertEqual(finding.location, "pkg/mod.py:1:1")
        self.assertEqual(
            [item["column"] for item in finding.measurement["occurrences"]],
            [1, 3],
        )
        self.assertEqual(len(finding.locations), 2)

    def test_allowed_characters_are_not_findings(self) -> None:
        data = (
            b"tab\there\n"
            b"crlf\r\n"
            b"line\n"
            b"\x0cpage\n"
            b"escape = \"\\r\"\n"
        )
        self.assertEqual(self.findings_for(data), [])

    def test_undecodable_file_is_a_decode_finding(self) -> None:
        findings = self.findings_for(b"good\nbad:\xff\n")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.subject, "pkg/mod.py:decode")
        self.assertEqual(finding.value, 1)
        self.assertEqual(finding.location, "pkg/mod.py:byte 9")
        self.assertEqual(finding.measurement["byte_offset"], 9)
        self.assertEqual(finding.measurement["line"], 2)
        self.assertEqual(finding.measurement["column"], 5)

    def test_undecodable_file_scans_ascii_controls_only(self) -> None:
        findings = self.findings_for(b"\x00\x85\xff\n")
        self.assertEqual(
            [finding.subject for finding in findings],
            ["pkg/mod.py:U+0000", "pkg/mod.py:decode"],
        )
        self.assertEqual(findings[0].measurement["column"], 1)
        self.assertEqual(findings[1].measurement["byte_offset"], 1)

    def test_unreadable_file_is_an_error_not_a_pass(self) -> None:
        with self.assertRaises(GateError):
            measure_source_chars(self.repo, ["missing.py"])


class SourceCharsCheckTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(source_chars_config())

    def run_source_check(self) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result, document = self.run_json()
        return result, document, self.check_by_id(document, "source-chars")

    def finding(
        self, check: dict[str, Any], subject: str
    ) -> dict[str, Any]:
        for item in check["findings"]:
            if item["subject"] == subject:
                return item
        self.fail(f"no finding {subject!r} in {check['findings']!r}")

    def test_rejected_character_fails_through_the_check(self) -> None:
        self.add_file("pkg/mod.py", b"VALUE = 1\x00\n")
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(check["outcome"], "fail")
        finding = self.finding(check, "pkg/mod.py:U+0000")
        self.assertEqual(finding["location"], "pkg/mod.py:1:10")
        self.assertEqual(finding["measurement"]["codepoint"], "U+0000")

    def test_fixed_allow_and_deny_tables_are_accepted(self) -> None:
        self.write_config(
            source_chars_config(
                extra=f"allow = {ALLOW}\ndeny = {DENY}\n"
            )
        )
        self.add_file("pkg/mod.py", "VALUE = 1\t\n")
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")

    def test_allow_or_deny_cannot_change_the_character_table(self) -> None:
        for key, value in (
            ("allow", '["tab"]'),
            ("deny", '["nul"]'),
        ):
            with self.subTest(key=key):
                self.write_config(
                    source_chars_config(extra=f"{key} = {value}\n")
                )
                result = self.run_qg("check")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(key, output(result))

    def test_invalid_scope_is_a_configuration_error(self) -> None:
        self.write_config(
            source_chars_config(extra='scope = "tree"\n')
        )
        result = self.run_qg("check")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("scope", output(result))

    def test_undecodable_file_fails_through_the_check(self) -> None:
        self.add_file("pkg/mod.py", b"VALUE = 1\n\xff\n")
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        finding = self.finding(check, "pkg/mod.py:decode")
        self.assertEqual(finding["location"], "pkg/mod.py:byte 10")

    def test_baseline_entry_accepts_exactly_its_subject(self) -> None:
        self.add_file("pkg/mod.py", b"VALUE = 1\x00\n")
        self.add_file(
            BASELINE,
            source_chars_baseline([character_entry("pkg/mod.py:U+0000")]),
        )
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertTrue(check["satisfied"])
        nul = self.finding(check, "pkg/mod.py:U+0000")
        self.assertTrue(nul["covered_by_baseline"])

        self.add_file("pkg/mod.py", b"VALUE = 1\x00\x1b\n")
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertTrue(self.finding(check, "pkg/mod.py:U+0000")["covered_by_baseline"])
        self.assertFalse(self.finding(check, "pkg/mod.py:U+001B")["covered_by_baseline"])

    def test_baseline_entry_accepts_a_decode_subject(self) -> None:
        self.add_file("pkg/mod.py", b"VALUE = 1\n\xff\n")
        self.add_file(
            BASELINE,
            source_chars_baseline([character_entry("pkg/mod.py:decode")]),
        )
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        finding = self.finding(check, "pkg/mod.py:decode")
        self.assertTrue(finding["covered_by_baseline"])

    def test_baseline_bound_rejects_an_increased_count(self) -> None:
        self.add_file("pkg/mod.py", b"\x00\x00\n")
        self.add_file(
            BASELINE,
            source_chars_baseline([character_entry("pkg/mod.py:U+0000")]),
        )
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        finding = self.finding(check, "pkg/mod.py:U+0000")
        self.assertEqual(finding["value"], 2)
        self.assertEqual(finding["bound"], 1)
        self.assertFalse(finding["covered_by_baseline"])

    def test_changed_scope_honours_tracked_and_untracked_files(self) -> None:
        self.add_file("pkg/tracked.py", "VALUE = 1\n")
        self.commit_all()
        self.add_file("pkg/tracked.py", b"VALUE = 1\x00\n")
        self.add_file("pkg/untracked.py", b"VALUE = 2\x1b\n")
        self.write_config(
            source_chars_config(
                extra='scope = "changed"\nbase = "HEAD"\n'
                "include_untracked = false\n"
            )
        )
        result, _document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["pkg/tracked.py:U+0000"],
        )

        self.write_config(
            source_chars_config(
                extra='scope = "changed"\nbase = "HEAD"\n'
                "include_untracked = true\n"
            )
        )
        result, _document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["pkg/tracked.py:U+0000", "pkg/untracked.py:U+001B"],
        )

    def test_malformed_baseline_is_an_error_not_a_pass(self) -> None:
        self.add_file(BASELINE, "not = a valid [ baseline\n")
        result, document, check = self.run_source_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(check["outcome"], "error")
        self.assertIn("invalid baseline", check["reason"])


class RepositoryReplayTests(unittest.TestCase):
    def test_this_repository_passes_source_chars(self) -> None:
        # The check is not enabled in this repository's own policy yet: the
        # trusted gate that judges a candidate comes from the base revision,
        # whose adapter registry cannot name source_chars, so enabling it here
        # would make every candidate policy unparseable. Replay the adapter on
        # this tree instead, which is the measurement the design asks for.
        findings = measure_source_chars(GATE, enumerate_files(GATE))
        self.assertEqual(findings, [])
