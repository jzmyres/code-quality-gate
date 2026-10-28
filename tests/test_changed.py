"""End-to-end change-scoped checks against disposable Git repositories."""
from __future__ import annotations

import unittest
from unittest import mock

from support import (
    BASE_CONFIG, GATE, PYTHON_TEST_HEADER, FixtureCase, baseline_text, output, sarif_report, with_clones,
)
from test_owners import baseline as owners_baseline, owner_config, pattern, rule, subject
from test_python_crap import crap_config
from test_verification import executed_entry, exclusion_entry, verification_baseline, verification_config
from quality_gate.changes import changed_lines, resolve_revision
from quality_gate import changes
from quality_gate.policy import UsageError
from quality_gate.runner import RunResult


LEGACY = (
    "def legacy(value):\n"
    "    if value:\n"
    "        if value > 1:\n"
    "            return 1\n"
    "    return 2\n"
)


class ChangedCrapTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/legacy.py", LEGACY)
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_ok(self):\n        self.assertTrue(True)\n",
        )
        self.write_config(crap_config())
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text(
                [
                    {"subject": "pkg/legacy.py:legacy", "bound": 12, "reason": "old"},
                    {"subject": "pkg/new.py:legacy", "bound": 12, "reason": "reserved"},
                ],
                check="crap", metric_version="python-lines/1",
            ),
        )
        self.commit_all()

    def check(self, *args: str):
        result, document = self.run_json(*args, env=self.default_tool_env())
        return result, document, self.check_by_id(document, "crap")

    def finding(self, check, subject_name="pkg/legacy.py:legacy"):
        return next(item for item in check["findings"] if item["subject"] == subject_name)

    def rejected_with_flag_only(self):
        plain, _, _ = self.check()
        self.assertEqual(plain.returncode, 0, output(plain))
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        return check

    def test_edit_inside_baselined_function_fails_and_refuses_prune(self) -> None:
        self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 10"))
        before = self.read_file("quality-gate-crap.toml")
        plain, _, _ = self.check()
        self.assertEqual(plain.returncode, 0, output(plain))
        result, document, check = self.check("--changed-from", "HEAD", "--prune", "crap")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertFalse(document["prune"]["performed"])
        self.assertEqual(self.read_file("quality-gate-crap.toml"), before)
        finding = self.finding(check)
        self.assertTrue(finding["covered_by_baseline"])
        self.assertTrue(finding["blocking"])
        self.assertTrue(finding["on_changed_lines"])
        self.assertEqual(finding["locations"], [{"path": "pkg/legacy.py", "start_line": 1, "end_line": 5}])
        self.assertIn("threshold violation on changed lines", result.stderr)

    def test_clean_changed_function_passes_even_with_passing_measurements(self) -> None:
        self.add_file("pkg/clean.py", "def clean(value):\n    return value + 1\n")
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.finding(check, "pkg/clean.py:clean")
        self.assertLessEqual(finding["value"], finding["threshold"])
        self.assertTrue(finding["on_changed_lines"])
        self.assertFalse(finding["blocking"])

    def test_unchanged_baselined_function_passes_with_other_edits(self) -> None:
        self.add_file("README.md", "# changed\n")
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(self.finding(check)["on_changed_lines"])
        self.assertTrue(check["satisfied"])

    def test_untracked_function_cannot_use_a_preexisting_baseline(self) -> None:
        self.add_file("pkg/new.py", LEGACY)
        check = self.rejected_with_flag_only()
        self.assertTrue(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])

    def test_untracked_symlink_cannot_use_a_preexisting_baseline(self) -> None:
        (self.repo / "pkg/new.py").symlink_to("legacy.py")
        check = self.rejected_with_flag_only()
        self.assertTrue(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])

    def test_unchanged_symlink_tracks_edits_to_its_inventoried_target(self) -> None:
        (self.repo / "pkg/new.py").symlink_to("legacy.py")
        self.commit_all("link")
        self.add_file("README.md", "# unrelated\n")
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])
        self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 10"))
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertTrue(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])

    def test_retargeted_symlink_marks_the_target_lines_as_new(self) -> None:
        link = self.repo / "pkg/new.py"
        link.symlink_to("legacy.py")
        self.commit_all("link")
        link.unlink()
        link.symlink_to("./legacy.py")
        check = self.rejected_with_flag_only()
        self.assertTrue(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])

    def test_external_symlink_target_is_reported_as_not_change_scoped(self) -> None:
        external = self.base / "external.py"
        external.write_text(LEGACY, encoding="utf-8")
        (self.repo / "pkg/new.py").symlink_to(external)
        self.commit_all("external link")
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["location_coverage"], "partial")
        self.assertIsNone(self.finding(check, "pkg/new.py:legacy")["on_changed_lines"])
        self.assertIn("not change-scoped (source target is outside the comparable inventory)", result.stderr)

    def test_moved_function_is_judged_at_its_new_lines(self) -> None:
        anchors = "".join(f"VALUE_{index} = {index}\n" for index in range(20))
        self.add_file("pkg/legacy.py", LEGACY + anchors)
        self.commit_all("old location")
        self.add_file("pkg/legacy.py", anchors + LEGACY)
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        finding = self.finding(check)
        self.assertEqual(finding["locations"][0]["start_line"], 21)
        self.assertTrue(finding["on_changed_lines"])

    def test_deletion_only_does_not_create_changed_lines(self) -> None:
        self.add_file("pkg/legacy.py", LEGACY.replace("    return 2", "    # old comment\n    return 2"))
        self.commit_all("comment")
        self.add_file("pkg/legacy.py", LEGACY)
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(self.finding(check)["on_changed_lines"])

    def test_staged_and_unstaged_content_are_compared_as_the_worktree(self) -> None:
        self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 10"))
        self.git("add", "pkg/legacy.py")
        self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 11"))
        result, _, _ = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        self.add_file("pkg/legacy.py", LEGACY)
        result, _, _ = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))

    def test_index_flags_cannot_hide_a_changed_baselined_function(self) -> None:
        for flag, reset in (("--assume-unchanged", "--no-assume-unchanged"),
                            ("--skip-worktree", "--no-skip-worktree")):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "pkg/legacy.py")
                self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 10"))
                result, _, check = self.check("--changed-from", "HEAD")
                self.assertEqual(result.returncode, 1, output(result))
                self.assertTrue(self.finding(check)["on_changed_lines"])
                self.git("update-index", reset, "pkg/legacy.py")
                self.add_file("pkg/legacy.py", LEGACY)

    def test_carriage_return_lines_use_source_line_numbers(self) -> None:
        source = "HEADER = 1\n" + LEGACY
        self.add_file("pkg/legacy.py", source.replace("\n", "\r").encode())
        self.commit_all("old-style line endings")
        self.add_file("pkg/legacy.py", source.replace("return 1", "return 10").replace("\n", "\r").encode())
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertTrue(self.finding(check)["on_changed_lines"])
        unchanged_function = source.replace("HEADER = 1", "HEADER = 2").replace("\n", "\r")
        self.add_file("pkg/legacy.py", unchanged_function.encode())
        result, _, check = self.check("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(self.finding(check)["on_changed_lines"])

    def test_minimum_threshold_uses_its_direction(self) -> None:
        self.write_config(crap_config(threshold=20).replace(
            '[checks.crap]\n', '[checks.crap]\ndirection = "min"\n'
        ))
        self.add_file("quality-gate-crap.toml", baseline_text([
            {"subject": "pkg/legacy.py:legacy", "bound": 12, "reason": "old"},
            {"subject": "pkg/legacy.py:<module>", "bound": 1, "reason": "old"},
        ], check="crap", metric_version="python-lines/1"))
        self.commit_all("minimum")
        self.add_file("pkg/legacy.py", LEGACY.replace("return 1", "return 10"))
        check = self.rejected_with_flag_only()
        self.assertTrue(self.finding(check)["blocking"])


class ChangedVerificationTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/mod.py", "A = 1  # noqa: E501\nB = 2  # noqa: E501\n")
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_ok(self):\n        self.assertTrue(True)\n",
        )
        self.write_config(verification_config())
        self.add_file(
            "quality-gate-verification.toml",
            verification_baseline([executed_entry(1), exclusion_entry("pkg/mod.py", "noqa", 2)]),
        )
        self.commit_all()

    def test_later_suppression_replacement_is_not_hidden_by_first_or_count(self) -> None:
        self.add_file("pkg/mod.py", "A = 1  # noqa: E501\nB = 3  # noqa: E701\n")
        env = self.default_tool_env()
        plain, _ = self.run_json(env=env)
        self.assertEqual(plain.returncode, 0, output(plain))
        result, document = self.run_json("--changed-from", "HEAD", env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "verification")
        finding = next(item for item in check["findings"] if item["subject"] == "exclusions:pkg/mod.py:noqa")
        self.assertEqual(finding["value"], 2)
        self.assertEqual(finding["locations"], [
            {"path": "pkg/mod.py", "start_line": 1, "end_line": 1},
            {"path": "pkg/mod.py", "start_line": 2, "end_line": 2},
        ])
        self.assertTrue(finding["on_changed_lines"])
        self.assertEqual(check["location_coverage"], "partial")
        self.assertIn("test counts are not change-scoped", result.stderr)

    def test_later_coverage_pragma_is_also_located(self) -> None:
        pragma = "# pragma: " "no cover"
        self.add_file("pkg/mod.py", f"A = 1  {pragma}\nB = 2  {pragma}\n")
        self.add_file(
            "quality-gate-verification.toml",
            verification_baseline([executed_entry(1), exclusion_entry("pkg/mod.py", "no-cover", 2)]),
        )
        self.commit_all("pragmas")
        self.add_file("pkg/mod.py", f"A = 1  {pragma}\nB = 3  {pragma}\n")
        result, document = self.run_json("--changed-from", "HEAD", env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "verification")
        finding = next(
            item for item in check["findings"] if item["subject"] == "exclusions:pkg/mod.py:no-cover"
        )
        self.assertEqual([item["start_line"] for item in finding["locations"]], [1, 2])
        self.assertTrue(finding["on_changed_lines"])


class ChangedOwnersTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.add_file("a.py", "sensitive()\n")
        self.add_file("other.py", "sensitive()\nsensitive()\n")
        self.write_config(owner_config([rule([pattern("python-call", "sensitive")])]))
        key = subject("single-owner", "other.py", "python-call", "sensitive")
        self.add_file("owners-baseline.toml", owners_baseline([(key, 2, "old")]))
        self.commit_all()

    def test_later_owner_occurrence_is_change_scoped(self) -> None:
        self.add_file("other.py", "sensitive()\nsensitive(42)\n")
        result, document = self.run_json("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "arch")
        self.assertEqual(check["location_coverage"], "complete")
        self.assertEqual([span["start_line"] for span in check["findings"][0]["locations"]], [1, 2])
        self.assertTrue(check["findings"][0]["blocking"])

    def test_trusted_policy_and_change_scope_can_use_same_base(self) -> None:
        self.add_file("tools.lock.toml", (GATE / "tools.lock.toml").read_text())
        self.commit_all("trusted base")
        self.add_file("other.py", "sensitive()\nsensitive(42)\n")
        result, document = self.run_json("--policy-from", "HEAD", "--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["schema"], 3)
        self.assertEqual(document["changed_from"], document["trust"]["policy_from"])
        self.assertTrue(self.check_by_id(document, "arch")["findings"][0]["blocking"])

    def test_replace_refs_do_not_change_the_diff_base(self) -> None:
        base = self.git("rev-parse", "HEAD").stdout.strip()
        self.add_file("other.py", "sensitive()\nsensitive(42)\n")
        self.commit_all("candidate")
        candidate = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("replace", base, candidate)
        result, document = self.run_json("--changed-from", base)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertTrue(self.check_by_id(document, "arch")["findings"][0]["on_changed_lines"])

    def test_candidate_clean_filter_cannot_hide_a_changed_occurrence(self) -> None:
        self.git("config", "filter.hide.clean", "cat >/dev/null; printf 'sensitive()\\nsensitive()\\n'")
        attributes = self.repo / ".git" / "info" / "attributes"
        attributes.write_text("other.py filter=hide\n", encoding="utf-8")
        self.add_file("other.py", "sensitive()\nsensitive(42)\n")
        self.assertEqual(self.git("diff", "HEAD", "--", "other.py").stdout, "")
        result, document = self.run_json("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertTrue(self.check_by_id(document, "arch")["findings"][0]["on_changed_lines"])


class ChangedCloneTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.add_file("a.py", "print('old a')\n")
        self.add_file("b.py", "print('old b')\n")
        self.write_config(with_clones())
        self.add_file("quality-gate-clones.toml", baseline_text([
            {"subject": "fp1", "bound": 1, "files": ["a.py", "b.py"], "reason": "old"}
        ]))
        self.commit_all()

    def test_either_clone_range_can_trigger_failure(self) -> None:
        env = self.install_fake_jscpd(sarif_report([("fp1", [("a.py", 1, 1), ("b.py", 1, 1)])]))
        for name in ("a.py", "b.py"):
            with self.subTest(name=name):
                original = self.read_file(name)
                self.add_file(name, "print('changed')\n")
                result, document = self.run_json("--changed-from", "HEAD", env=env)
                self.assertEqual(result.returncode, 1, output(result))
                finding = self.check_by_id(document, "clones")["findings"][0]
                self.assertEqual({span["path"] for span in finding["locations"]}, {"a.py", "b.py"})
                self.assertTrue(finding["on_changed_lines"])
                self.add_file(name, original)

    def test_incomplete_clone_evidence_is_reported_and_uses_ratchet(self) -> None:
        report = sarif_report([("fp1", [("a.py", 1, 1), ("b.py", 1, 1)])])
        del report["runs"][0]["results"][0]["relatedLocations"][0]["physicalLocation"]["region"]["endLine"]
        env = self.install_fake_jscpd(report)
        self.add_file("b.py", "print('changed')\n")
        result, document = self.run_json("--changed-from", "HEAD", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["location_coverage"], "partial")
        self.assertIsNone(check["findings"][0]["locations"])
        self.assertIn("not change-scoped (incomplete locations)", result.stderr)

    def test_located_advisory_violation_on_changed_lines_still_fails(self) -> None:
        self.write_config(with_clones(enforcement="advisory"))
        self.commit_all("advisory")
        env = self.install_fake_jscpd(sarif_report([("fp1", [("a.py", 1, 1), ("b.py", 1, 1)])]))
        self.add_file("a.py", "print('changed')\n")
        result, document = self.run_json("--changed-from", "HEAD", env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "clones")
        self.assertFalse(check["satisfied"])
        self.assertTrue(check["findings"][0]["blocking"])


class ChangedGitTests(FixtureCase):
    def test_nonlocated_checks_are_named_and_clean_change_passes(self) -> None:
        self.commit_all()
        self.add_file("a.py", "print('changed')\n")
        result, document = self.run_json("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.check_by_id(document, "smoke")["location_coverage"], "none")
        self.assertIn("check: smoke: not change-scoped", result.stderr)
        self.assertEqual(document["changed_from"], self.git("rev-parse", "HEAD").stdout.strip())

    def test_bad_revision_is_a_named_error(self) -> None:
        self.commit_all()
        result, document = self.run_json("--changed-from", "missing-qf19-revision")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("missing-qf19-revision", document["error"])

    def test_unlocated_advisory_failure_keeps_its_ordinary_judgement(self) -> None:
        self.write_config(BASE_CONFIG + '\n[checks.extra]\nadapter = "command"\ntier = 1\n'
                          'enforcement = "advisory"\nrun = ["python3", "-c", "raise SystemExit(7)"]\n')
        self.commit_all()
        self.add_file("a.py", "print('changed')\n")
        result, document = self.run_json("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertTrue(self.check_by_id(document, "extra")["satisfied"])
        self.assertIn("check: extra: not change-scoped", result.stderr)

    def test_literal_git_paths_and_stageable_files(self) -> None:
        name = ":odd name\n雪.py"
        self.add_file(name, "first\nsecond\n")
        self.commit_all()
        self.add_file(name, "first\nchanged\n")
        self.add_file("staged.py", "staged\n")
        self.git("add", "staged.py")
        self.add_file("untracked.py", "untracked\n")
        revision = resolve_revision(self.repo, "HEAD")
        changes = changed_lines(self.repo, revision, [name, "staged.py", "untracked.py"])
        self.assertEqual(changes[name], [(2, 2)])
        self.assertEqual(changes["staged.py"][0][0], 1)
        self.assertEqual(changes["untracked.py"][0][0], 1)

    def test_unchanged_symlink_uses_its_target_and_a_replacement_is_new(self) -> None:
        link = self.repo / "link.py"
        link.symlink_to("a.py")
        self.commit_all()
        revision = resolve_revision(self.repo, "HEAD")
        self.assertEqual(changed_lines(self.repo, revision, ["link.py", "a.py"])["link.py"], [])
        link.unlink()
        self.add_file("link.py", "print('replacement')\n")
        self.assertEqual(changed_lines(self.repo, revision, ["link.py"])["link.py"][0][0], 1)

    def test_changing_only_carriage_return_line_endings_marks_all_lines(self) -> None:
        self.add_file("a.py", b"first\rsecond\r")
        self.commit_all()
        self.add_file("a.py", b"first\nsecond\n")
        revision = resolve_revision(self.repo, "HEAD")
        spans = changed_lines(self.repo, revision, ["a.py"])["a.py"]
        self.assertLessEqual(spans[0][0], 1)
        self.assertGreaterEqual(spans[0][1], 2)

    def test_diff_errors_are_named_and_never_silently_treated_as_clean(self) -> None:
        with self.assertRaisesRegex(UsageError, "cannot compare.*missing.py"):
            changes._candidate_bytes(self.repo / "missing.py")
        failed = RunResult(argv=(), execution="completed", returncode=2, stderr=b"diff failure")
        with mock.patch.object(changes, "run", return_value=failed):
            with self.assertRaisesRegex(UsageError, "cannot diff a.py: diff failure"):
                changes._diff_bytes(self.repo, self.base, b"old", b"new", "a.py")

    def test_candidate_fsmonitor_is_never_run_for_change_diff(self) -> None:
        self.commit_all()
        marker = self.base / "monitor-ran"
        monitor = self.base / "monitor"
        monitor.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        monitor.chmod(0o755)
        self.git("config", "core.fsmonitor", str(monitor))
        self.add_file("a.py", "print('changed')\n")
        result, _ = self.run_json("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
