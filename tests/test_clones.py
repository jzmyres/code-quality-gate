"""Tests for the duplicate-code ratchet, including the real jscpd binary."""
from __future__ import annotations

import importlib
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from support import (
    GATE,
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)

sys.path.insert(0, str(GATE))
checks = importlib.import_module("quality_gate.checks")
clones = importlib.import_module("quality_gate.clones")
policy = importlib.import_module("quality_gate.policy")
runner = importlib.import_module("quality_gate.runner")

ELISP_SOURCE = """\
;;; sample.el --- file summary -*- lexical-binding: t; -*-
(defun qg-summarize-files (paths)
  "Return a summary of PATHS."
  (let ((count 0)
        (total 0))
    (dolist (path paths)
      (when (file-regular-p path)
        (setq count (1+ count))
        (setq total (+ total (file-attribute-size (file-attributes path))))))
    (format "%d files, %d bytes" count total)))
(provide 'sample)
;;; sample.el ends here
"""

SHELL_SOURCE = """\
#!/bin/bash
set -euo pipefail
summarize_files() {
  local count=0
  local total=0
  for path in "$@"; do
    if [[ -f "$path" ]]; then
      count=$((count + 1))
      total=$((total + $(wc -c < "$path")))
    fi
  done
  printf '%s files, %s bytes\\n' "$count" "$total"
}
summarize_files "$@"
"""


class CloneGateTests(FixtureCase):
    def clone_env(
        self,
        clones: list[tuple[str, list[tuple[str, int, int]]]],
        entries: list[dict[str, object]] | None = None,
        *,
        classes: str = '["python"]',
        min_tokens: int = 50,
        baseline: str = "quality-gate-clones.toml",
        fake: dict[str, object] | None = None,
    ) -> dict[str, str]:
        self.add_file("b.py", "print('b')\n")
        self.write_config(
            with_clones(
                classes=classes,
                min_tokens=min_tokens,
                baseline=baseline,
            )
        )
        if entries is not None:
            self.add_file(baseline, baseline_text(entries))
        return self.install_fake_jscpd(
            sarif_report(clones), **(fake or {})
        )

    def mirror_entries(
        self,
        *,
        bound: int = 3,
        expires: str | None = None,
        reason: str = "deliberate mirror",
    ) -> list[dict[str, object]]:
        entry: dict[str, object] = {
            "fingerprint": "fp1",
            "count": bound,
            "files": ["a.py", "b.py"],
            "reason": reason,
        }
        if expires is not None:
            entry["expires"] = expires
        return [entry]

    def clone_failure(
        self, env: dict[str, str], *needles: str, prune: bool = False
    ) -> str:
        command = ("check", "--prune", "clones") if prune else ("check",)
        result = self.run_qg(*command, env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        for needle in needles:
            self.assertIn(needle, text)
        return text

    def unsupported_clone(
        self, env: dict[str, str], *needles: str
    ) -> str:
        result, document = self.run_json(env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIsInstance(check["reason"], str)
        for needle in needles:
            self.assertIn(needle, text)
        return text

    def single_baseline(self, fingerprint: str, reason: str) -> dict[str, object]:
        entries = tomllib.loads(
            self.read_file("quality-gate-clones.toml")
        )["entry"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["subject"], fingerprint)
        self.assertEqual(entry["bound"], 1)
        self.assertEqual(entry["reason"], reason)
        return entry

    def test_baselined_clone_passes(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "files": ["a.py", "b.py"],
                    "reason": "deliberate mirror",
                }
            ],
        )
        result = self.run_qg("check", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("clones: 1 clone within baseline", result.stdout)

    def test_new_clone_fails_with_files_and_ranges(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 2, 9)])]
        )
        self.clone_failure(env, "new clone fp1", "a.py:1-8", "b.py:2-9")

    def repeated_clone_env(
        self,
        entries: list[dict[str, object]],
        extra: tuple[str, list[tuple[str, int, int]]] | None = None,
    ) -> dict[str, str]:
        clones = [
            ("fp1", [("a.py", 1, 8), ("b.py", 1, 8)]),
            ("fp1", [("a.py", 1, 8), ("c.py", 1, 8)]),
        ]
        if extra is not None:
            clones.append(extra)
        env = self.clone_env(clones, entries)
        self.add_file("c.py", "print('c')\n")
        return env

    def test_count_exceeded_fails(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "reason": "one accepted copy"}]
        )
        self.clone_failure(
            env, "occurs 2 times", "b.py:1-8", "c.py:1-8"
        )

    def test_count_allows_repeated_fingerprint(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "count": 2, "reason": "two accepted copies"}]
        )
        result = self.run_qg("check", env=env)
        self.assertEqual(result.returncode, 0, output(result))

    def test_empty_baseline_reason_fails(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [{"fingerprint": "fp1", "reason": "   "}],
        )
        self.clone_failure(
            env, "empty reason", "a.py:1-8", "b.py:1-8"
        )

    def test_resolved_entry_is_reported_but_passes(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "files": ["old.py"], "reason": "gone"}],
        )
        result = self.run_qg("check", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("resolved fp-old", result.stdout)

    def test_resolved_entry_with_empty_reason_fails(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "files": ["old.py"], "reason": "   "}],
        )
        text = self.clone_failure(env, "empty reason", "resolved fp-old")
        self.assertIn("files: old.py", text)

    def test_entry_outside_the_selected_files_is_unmeasured_and_kept(self) -> None:
        env = self.clone_env(
            [],
            [
                {
                    "fingerprint": "fp-other",
                    "files": ["README.md"],
                    "reason": "another class is not in this scan",
                }
            ],
        )
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "clones")
        self.assertTrue(check["satisfied"])
        self.assertEqual(check["resolved_baseline_entries"], [])
        self.assertEqual(
            check["unmeasured_baseline_entries"], ["fp-other"]
        )
        self.assertIn("unmeasured fp-other", result.stderr)
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        loaded = tomllib.loads(self.read_file("quality-gate-clones.toml"))
        self.assertEqual(loaded["entry"][0]["subject"], "fp-other")

    def run_resolved(
        self, entry: dict[str, object]
    ) -> tuple[object, dict[str, object]]:
        env = self.clone_env([], [entry])
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 0, output(result))
        return result, self.check_by_id(document, "clones")

    def test_entry_whose_file_was_deleted_is_resolved(self) -> None:
        result, check = self.run_resolved(
            {
                "fingerprint": "fp-old",
                "files": ["deleted.py"],
                "reason": "the file was deleted",
            }
        )
        self.assertEqual(check["resolved_baseline_entries"], ["fp-old"])
        self.assertEqual(check["unmeasured_baseline_entries"], [])
        self.assertIn("resolved fp-old", result.stderr)

    def test_entry_with_every_selected_file_resolves(self) -> None:
        _result, check = self.run_resolved(
            {
                "fingerprint": "fp-gone",
                "files": ["a.py", "b.py"],
                "reason": "the clone is gone",
            }
        )
        self.assertEqual(check["resolved_baseline_entries"], ["fp-gone"])

    def test_absent_baseline_with_no_clones_passes(self) -> None:
        env = self.clone_env([])
        result = self.run_qg("check", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("clones: 0 clones", result.stdout)

    def test_absent_baseline_with_clone_fails(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])]
        )
        self.clone_failure(env, "new clone fp1")

    def test_jscpd_signal_is_a_raw_fail(self) -> None:
        env = self.clone_env([], fake={"signal_number": 15})
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["execution"], "signal")
        self.assertEqual(check["diagnostics"]["signal"], 15)
        self.assertIn("terminated by signal", check["reason"])

    def test_unsupported_clone_carries_the_structured_reason(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text('{"version": "2.1.0"}', encoding="utf-8")
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn("no completed jscpd run", check["reason"])

    def test_jscpd_nonzero_exit_fails(self) -> None:
        env = self.clone_env(
            [],
            fake={"exit_code": 3, "error": "boom from jscpd"},
        )
        self.clone_failure(env, "jscpd failed (exit 3)", "boom from jscpd")

    def test_jscpd_without_report_fails(self) -> None:
        env = self.clone_env([], fake={"report": False})
        self.clone_failure(env, "wrote no report")

    def test_jscpd_empty_analysis_fails(self) -> None:
        env = self.clone_env(
            [],
            fake={
                "exit_code": 1,
                "error": "ERROR: jscpd analyzed no files (--fail-on-empty)",
            },
        )
        self.clone_failure(env, "jscpd failed", "analyzed no files")

    def test_jscpd_is_invoked_with_the_gate_options_and_files(self) -> None:
        args_file = self.base / "jscpd-args.txt"
        self.write_config(
            with_clones(min_tokens=77).replace(
                "[code]",
                "[hygiene]\nmax_bytes = 12345\n\n[code]",
            )
        )
        env = self.install_fake_jscpd(
            sarif_report([]), args_file=args_file
        )
        result = self.run_qg("check", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        arguments = args_file.read_text(encoding="utf-8").split("\n")
        self.assertIn("--fail-on-empty", arguments)
        self.assertIn("--reporters", arguments)
        self.assertIn("json,sarif", arguments)
        self.assertIn("--no-gitignore", arguments)
        self.assertIn("--config", arguments)
        index = arguments.index("--min-tokens")
        self.assertEqual(arguments[index + 1], "77")
        index = arguments.index("--min-lines")
        self.assertEqual(arguments[index + 1], "5")
        index = arguments.index("--max-size")
        self.assertEqual(arguments[index + 1], "12345")
        index = arguments.index("--ignore")
        self.assertTrue(arguments[index + 1])
        separator = arguments.index("--")
        self.assertIn("a.py", arguments[separator + 1:])

    def test_jscpd_source_count_mismatch_is_unsupported(self) -> None:
        env = self.clone_env(
            [],
            fake={
                "json_report": {
                    "statistics": {
                        "formats": {},
                        "total": {"sources": 1},
                    }
                }
            },
        )
        self.unsupported_clone(env, "not analysed", "b.py")

    def test_malformed_jscpd_json_is_unsupported(self) -> None:
        cases = [
            ({"statistics": "x"}, "statistics is not an object"),
            (
                {"statistics": {"total": "x"}},
                "statistics.total is not an object",
            ),
            (
                {"statistics": {"total": {"sources": "2"}}},
                "statistics.total.sources is not an integer",
            ),
            (
                {"statistics": {"formats": "x", "total": {"sources": 1}}},
                "not analysed",
            ),
            (
                {
                    "statistics": {
                        "formats": {"python": "x"},
                        "total": {"sources": 1},
                    }
                },
                "not analysed",
            ),
            (
                {
                    "statistics": {
                        "formats": {"python": {"sources": True}},
                        "total": {"sources": 1},
                    }
                },
                "not analysed",
            ),
            (
                {
                    "statistics": {
                        "formats": {"python": {"sources": "2"}},
                        "total": {"sources": 1},
                    }
                },
                "not analysed",
            ),
            (
                {
                    "statistics": {
                        "formats": {"python": {"sources": 2}},
                        "total": {"sources": 1},
                    }
                },
                "not analysed: a.py, b.py",
            ),
        ]
        for report, needle in cases:
            with self.subTest(report=report):
                env = self.clone_env([], fake={"json_report": report})
                self.unsupported_clone(env, needle)

    def test_invalid_sarif_is_unsupported(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text('{"version": "2.1.0"}', encoding="utf-8")
        self.unsupported_clone(env, "no completed jscpd run")

    def test_sarif_without_fingerprint_is_unsupported(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text(
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}, "results": [{}]}]}',
            encoding="utf-8",
        )
        self.unsupported_clone(
            env, "no completed jscpd run", "jscpdCloneHash/v1"
        )

    def test_sarif_needs_exactly_one_jscpd_run_with_results(self) -> None:
        cases = [
            '{"version": "2.1.0", "runs": []}',
            '{"version": "2.1.0", "runs": [{}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "other"}}, "results": []}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}, "results": []},'
            '{"tool": {"driver": {"name": "jscpd"}}, "results": []}]}',
        ]
        for report in cases:
            with self.subTest(report=report):
                env = self.clone_env([], fake={})
                sarif_path = self.base / "sarif.json"
                sarif_path.write_text(report, encoding="utf-8")
                self.clone_failure(env, "no completed jscpd run")

    def test_prune_removes_resolved_entries_and_lowers_count(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            self.mirror_entries()
            + [{"fingerprint": "fp-old", "files": ["old.py"], "reason": "gone"}],
        )
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        entry = self.single_baseline("fp1", "deliberate mirror")
        self.assertEqual(entry["files"], ["a.py", "b.py"])

    def test_prune_removes_an_empty_baseline(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "reason": "gone"}],
        )
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.repo / "quality-gate-clones.toml").exists())
        self.assertIn("baseline removed", result.stdout)

    def test_prune_with_absent_baseline_creates_nothing(self) -> None:
        env = self.clone_env([])
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.repo / "quality-gate-clones.toml").exists())
        self.assertNotIn("baseline removed", result.stdout)

    def test_prune_never_adds_or_raises_an_entry(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "reason": "one accepted copy"}],
            extra=("fp-new", [("d.py", 1, 8), ("e.py", 1, 8)]),
        )
        self.add_file("d.py", "print('d')\n")
        self.add_file("e.py", "print('e')\n")
        text = self.clone_failure(env, "new clone fp-new", prune=True)
        unchanged = tomllib.loads(
            self.read_file("quality-gate-clones.toml")
        )["entry"]
        self.assertEqual(unchanged[0]["subject"], "fp1")
        self.assertEqual(unchanged[0]["bound"], 1)
        self.assertNotIn("fp-new", self.read_file("quality-gate-clones.toml"))
        self.assertIn("occurs 2 times", text)
        self.assertIn("prune refused", text)

    def test_prune_does_not_rewrite_with_an_empty_reason(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {"fingerprint": "fp1", "reason": "   "},
                {"fingerprint": "fp-old", "reason": "gone"},
            ],
        )
        before = self.read_file("quality-gate-clones.toml")
        self.clone_failure(env, "empty reason", prune=True)
        self.assertEqual(self.read_file("quality-gate-clones.toml"), before)

    def test_missing_tool_names_tools_fetch(self) -> None:
        self.write_config(with_clones())
        env = {"QG_TOOLS_DIR": str(self.base / "empty-tools")}
        self.clone_failure(env, "tools fetch")

    def test_no_files_in_clone_classes_fails(self) -> None:
        self.write_config(with_clones(classes='["empty"]'))
        self.clone_failure({}, "no files selected")

    def test_expired_entry_no_longer_covers(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "expires": "2000-01-01",
                    "reason": "expired exception",
                }
            ],
        )
        self.clone_failure(env, "expired baseline entry", "2000-01-01")

    def test_check_prune_lowers_a_passing_baseline(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            self.mirror_entries(bound=3, reason="lower me"),
        )
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        entry = self.single_baseline("fp1", "lower me")
        self.assertEqual(entry["files"], ["a.py", "b.py"])

    def test_check_prune_reports_refusal_in_json(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "bound": 1, "reason": "only one"}]
        )
        result, document = self.run_json("--prune", "clones", env=env)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(document["prune"]["requested"], ["clones"])
        self.assertFalse(document["prune"]["performed"])
        self.assertIn("did not pass", document["prune"]["reason"])
        check = self.check_by_id(document, "clones")
        self.assertFalse(check["satisfied"])

    def test_prune_round_trips_expiry_files_and_headers(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            self.mirror_entries(expires="2999-01-01"),
        )
        result, document = self.run_json("--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            document["prune"],
            {"requested": ["clones"], "performed": True, "reason": None},
        )
        loaded = tomllib.loads(self.read_file("quality-gate-clones.toml"))
        self.assertEqual(loaded["check"], "clones")
        self.assertEqual(
            loaded["metric_version"], "jscpd-clone-occurrences/1"
        )
        entry = loaded["entry"][0]
        self.assertEqual(entry["subject"], "fp1")
        self.assertEqual(entry["bound"], 1)
        self.assertEqual(entry["files"], ["a.py", "b.py"])
        self.assertEqual(str(entry["expires"]), "2999-01-01")
        self.assertEqual(entry["reason"], "deliberate mirror")

    def test_check_prune_refuses_while_the_check_fails(self) -> None:
        env = self.clone_env(
            [
                ("fp1", [("a.py", 1, 8), ("b.py", 1, 8)]),
                ("fp1", [("a.py", 1, 8), ("c.py", 1, 8)]),
            ],
            [{"fingerprint": "fp1", "bound": 1, "reason": "only one"}],
        )
        self.add_file("c.py", "print('c')\n")
        before = self.read_file("quality-gate-clones.toml")
        result = self.run_qg("check", "--prune", "clones", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("prune refused", text)
        self.assertEqual(self.read_file("quality-gate-clones.toml"), before)

    def test_check_prune_unknown_id_exits_2(self) -> None:
        result = self.run_qg("check", "--prune", "mystery")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown check 'mystery'", text)

    def test_invalid_baseline_toml_fails(self) -> None:
        env = self.clone_env([])
        self.add_file("quality-gate-clones.toml", "[clone\n")
        self.clone_failure(env, "invalid baseline")

    def test_invalid_baseline_bound_fails(self) -> None:
        env = self.clone_env([])
        self.add_file(
            "quality-gate-clones.toml",
            'check = "clones"\nmetric_version = '
            '"jscpd-clone-occurrences/1"\n'
            '[[entry]]\nsubject = "fp1"\nbound = "high"\n'
            'reason = "never valid"\n',
        )
        self.clone_failure(env, "bound", "finite number")

    def test_non_finite_baseline_bound_fails(self) -> None:
        for value in ("inf", "-inf", "nan"):
            with self.subTest(value=value):
                env = self.clone_env([])
                self.add_file(
                    "quality-gate-clones.toml",
                    f'check = "clones"\nmetric_version = '
                    '"jscpd-clone-occurrences/1"\n'
                    f'[[entry]]\nsubject = "fp1"\nbound = {value}\n'
                    'reason = "never valid"\n',
                )
                result, document = self.run_json(env=env)
                self.assertEqual(result.returncode, 1, output(result))
                self.assertNotIn("Infinity", result.stdout)
                self.assertNotIn("NaN", result.stdout)
                self.assertEqual(document["decision"], "rejected")
                check = self.check_by_id(document, "clones")
                self.assertEqual(check["outcome"], "error")
                self.assertIn("finite number", result.stderr)

    def test_zero_count_rejects_an_occurrence(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [{"fingerprint": "fp1", "count": 0, "reason": "nothing accepted"}],
        )
        self.clone_failure(
            env, "occurs 1 time", "baseline bound 0"
        )

    def test_real_jscpd_reports_elisp_and_bash_clone_pairs(self) -> None:
        self.write_config(
            """\
schema = 2

[code]
patterns = ["*.el", "*.sh"]
shebangs = ["sh", "bash"]

[levels]
required_tiers = [1]

[classes.lisp]
code = true
description = "Emacs Lisp"
checks = ["clones", "tests"]

[classes.shell]
code = true
description = "Bash"
checks = ["clones", "tests"]

[classes.config]
code = false
description = "Configuration"

[[rule]]
pattern = "*.el"
class = "lisp"
reason = "Emacs Lisp source"

[[rule]]
pattern = "*.sh"
class = "shell"
reason = "Bash source"

[[rule]]
pattern = "*.toml"
class = "config"
reason = "Configuration"

[[rule]]
pattern = ".gitignore"
class = "config"
reason = "Ignore rules"

[checks.clones]
adapter = "clones"
tier = 1
enforcement = "enforced"
min_tokens = 50
baseline = "quality-gate-clones.toml"

[checks.tests]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "print('Ran 1 test in 0.001s')"]
tests_pattern = "^Ran (\\\\d+) tests? in"
"""
        )
        (self.repo / "a.py").unlink()
        (self.repo / "README.md").unlink()
        self.add_file("a.el", ELISP_SOURCE)
        self.add_file("b.el", ELISP_SOURCE)
        self.add_file("a.sh", SHELL_SOURCE)
        self.add_file("b.sh", SHELL_SOURCE)

        result = self.run_qg("check", env=self.default_tool_env())
        text = output(result)
        if "not installed" in text and "tools fetch" in text:
            self.fail(
                "real jscpd is not installed; run python3 -I qg.py tools fetch: "
                + text
            )
        self.assertEqual(result.returncode, 1, text)
        for name in ("a.el", "b.el", "a.sh", "b.sh"):
            self.assertIn(name, text)
        self.assertIn("new clone", text)
        new_clone_lines = [
            line for line in text.splitlines() if "new clone" in line
        ]
        self.assertTrue(
            any(
                "a.el" in line and "b.el" in line
                for line in new_clone_lines
            ),
            text,
        )
        self.assertTrue(
            any(
                "a.sh" in line and "b.sh" in line
                for line in new_clone_lines
            ),
            text,
        )


class CloneOutcomeTests(unittest.TestCase):
    def measurement(
        self, *, execution: str, unsupported: bool
    ) -> object:
        return clones.CloneMeasurement(
            [], runner.Diagnostics(), execution, "detail", unsupported
        )

    def test_budget_and_signal_are_raw_failures(self) -> None:
        for execution in ("budget", "signal"):
            with self.subTest(execution=execution):
                self.assertEqual(
                    checks._clone_outcome(
                        self.measurement(
                            execution=execution, unsupported=True
                        )
                    ),
                    "fail",
                )
        self.assertEqual(
            checks._clone_outcome(
                self.measurement(execution="error", unsupported=True)
            ),
            "unsupported",
        )
        self.assertEqual(
            checks._clone_outcome(
                self.measurement(execution="error", unsupported=False)
            ),
            "error",
        )


class SarifLocationTests(unittest.TestCase):
    root = Path("/repo")
    report = Path("report.sarif")

    def test_duplicate_results_are_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.sarif"
            report.write_text('{"runs":[{"tool":{"driver":{"name":"jscpd"}},'
                              '"results":[{}],"results":[]}]}', encoding="utf-8")
            with self.assertRaises(policy.UnsupportedError) as raised:
                clones._parse_sarif(report, self.root)
        message = str(raised.exception)
        self.assertIn("no completed jscpd run", message)
        self.assertIn("invalid JSON", message)
        self.assertIn("duplicate name 'results'", message)
        self.assertIn(str(report), message)

    def location(self, **physical: object) -> dict[str, object]:
        return {"physicalLocation": physical}

    def test_single_line_and_range(self) -> None:
        single = self.location(
            artifactLocation={"uri": "./a.py"},
            region={"startLine": 3},
        )
        self.assertEqual(
            clones._sarif_location(
                single, self.root, "runs[0].results[0]", self.report
            ),
            "a.py:3",
        )
        same = self.location(
            artifactLocation={"uri": "a.py"},
            region={"startLine": 3, "endLine": 3},
        )
        self.assertEqual(
            clones._sarif_location(
                same, self.root, "runs[0].results[0]", self.report
            ),
            "a.py:3",
        )
        span = self.location(
            artifactLocation={"uri": "a.py"},
            region={"startLine": 3, "endLine": 4},
        )
        self.assertEqual(
            clones._sarif_location(
                span, self.root, "runs[0].results[0]", self.report
            ),
            "a.py:3-4",
        )

    def test_malformed_location_is_unsupported(self) -> None:
        cases = [
            ({}, "missing location data"),
            ({"physicalLocation": "x"}, "missing location data"),
            (
                {"physicalLocation": {"artifactLocation": "x"}},
                "missing location data",
            ),
            (
                {"physicalLocation": {"artifactLocation": {"uri": 1}}},
                "location uri is not a string",
            ),
            (
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": "x",
                    }
                },
                "region is not an object",
            ),
            (
                self.location(
                    artifactLocation={"uri": "a.py"},
                    region={"startLine": "3"},
                ),
                "startLine is not an integer",
            ),
            (
                self.location(
                    artifactLocation={"uri": "a.py"},
                    region={"startLine": True},
                ),
                "startLine is not an integer",
            ),
            (
                self.location(
                    artifactLocation={"uri": "a.py"},
                    region={"startLine": 3, "endLine": "4"},
                ),
                "endLine is not an integer",
            ),
        ]
        for location, needle in cases:
            with self.subTest(location=location):
                with self.assertRaises(policy.UnsupportedError) as raised:
                    clones._sarif_location(
                        location,
                        self.root,
                        "runs[0].results[0]",
                        self.report,
                    )
                self.assertIn(needle, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
